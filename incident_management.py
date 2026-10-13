from dataclasses import dataclass
from datetime import datetime


#  Shared allowed values
CATEGORIES = (
    "Phishing / Suspicious Message",
    "Account Security",
    "Malware",
    "Unauthorized Access",
    "Other",
)

SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")
URGENCY_LEVELS = ("Low", "Medium", "High")
AFFECTED_SCOPES = (
    "One user",
    "Small group",
    "Department",
    "Organization",
)
STATUSES = ("Submitted", "Under Review", "Resolved", "Closed")

MAX_DESCRIPTION_LENGTH = 1000


#  Allowed status transitions
STATUS_TRANSITIONS = {
    "Submitted": ("Under Review",),
    "Under Review": ("Resolved", "Closed"),
    "Resolved": ("Under Review", "Closed"),
    "Closed": (),
}


#  Shared incident and action schemas
INCIDENT_FIELDS = (
    "incident_id",
    "reported_at",
    "category",
    "description",
    "severity",
    "urgency",
    "affected_scope",
    "priority_score",
    "status",
    "reviewed_at",
    "resolution",
)

ACTION_FIELDS = (
    "action_id",
    "incident_id",
    "action_type",
    "action_time",
    "note",
)


# Return the current date and time in a readable format
def now():
    return datetime.now().astimezone().strftime("%d/%m/%Y %I:%M %p")


# Check whether a date matches the required format.
def validate_datetime(value):
    try:
        datetime.strptime(value, "%d/%m/%Y %I:%M %p")
        return True
    except ValueError:
        return False


#  Incident class
@dataclass
class Incident:
    incident_id: str
    reported_at: str
    category: str
    description: str
    severity: str
    urgency: str
    affected_scope: str
    priority_score: int
    status: str = "Submitted"
    reviewed_at: str = ""
    resolution: str = ""

    #  Validate incident data
    def validate(self):
        text_fields = (
            self.incident_id,
            self.reported_at,
            self.category,
            self.description,
            self.severity,
            self.urgency,
            self.affected_scope,
            self.status,
            self.reviewed_at,
            self.resolution,
        )

        if not all(isinstance(value, str) for value in text_fields):
            raise ValueError("All incident text fields must contain text.")

        if (
            not self.incident_id.startswith("INC-")
            or not self.incident_id[4:].isdecimal()
        ):
            raise ValueError("Incident ID must look like INC-1001.")

        if not validate_datetime(self.reported_at):
            raise ValueError(
                "Reported date and time must use DD/MM/YYYY HH:MM AM/PM format."
            )

        if self.category not in CATEGORIES:
            raise ValueError("Choose a valid incident category.")

        if not self.description.strip():
            raise ValueError("Description cannot be empty.")

        if len(self.description.strip()) > MAX_DESCRIPTION_LENGTH:
            raise ValueError(
                "Description must be 1000 characters or fewer."
            )

        if self.severity not in SEVERITY_LEVELS:
            raise ValueError("Choose a valid severity.")

        if self.urgency not in URGENCY_LEVELS:
            raise ValueError("Choose a valid urgency.")

        if self.affected_scope not in AFFECTED_SCOPES:
            raise ValueError("Choose a valid affected scope.")

        if self.status not in STATUSES:
            raise ValueError("Choose a valid status.")

        if type(self.priority_score) is not int:
            raise ValueError("Priority score must be a whole number.")

        if self.priority_score != self.calculate_priority():
            raise ValueError(
                "Priority score must match severity and urgency."
            )

        if self.reviewed_at and not validate_datetime(self.reviewed_at):
            raise ValueError(
                "Review date and time must use DD/MM/YYYY HH:MM AM/PM format."
            )

        # A reviewed, resolved, or closed incident must have a review time.
        if self.status != "Submitted" and not self.reviewed_at:
            raise ValueError(
                "A reviewed incident must have a review date and time."
            )

        if self.status == "Resolved" and not self.resolution.strip():
            raise ValueError(
                "A resolved incident must have a resolution."
            )

    # Calculate preliminary priority
    def calculate_priority(self):
        if (
            not isinstance(self.severity, str)
            or self.severity not in SEVERITY_LEVELS
        ):
            raise ValueError("Choose a valid severity.")

        if (
            not isinstance(self.urgency, str)
            or self.urgency not in URGENCY_LEVELS
        ):
            raise ValueError("Choose a valid urgency.")

        severity_points = SEVERITY_LEVELS.index(self.severity) + 1
        urgency_points = URGENCY_LEVELS.index(self.urgency) + 1

        # Priority helps reviewers organize reports.

        return severity_points + urgency_points

    # Change status only when allowed
    def update_status(self, new_status, resolution=""):
        if not isinstance(new_status, str) or new_status not in STATUSES:
            raise ValueError("Choose a valid status.")

        if new_status == self.status:
            raise ValueError("The incident already has this status.")

        if new_status not in STATUS_TRANSITIONS.get(self.status, ()):
            raise ValueError(
                "Status cannot change from "
                + self.status
                + " to "
                + new_status
                + "."
            )

        if not isinstance(resolution, str):
            raise ValueError("Resolution must be text.")

        resolution = resolution.strip()

        # Resolution text is only accepted when resolving an incident.
        if new_status != "Resolved" and resolution:
            raise ValueError(
                "Resolution can only be provided when resolving an incident."
            )

        if new_status == "Resolved" and not resolution:
            raise ValueError(
                "A resolution is required to resolve an incident."
            )

        # Record the first review time.
        if new_status == "Under Review" and not self.reviewed_at:
            self.reviewed_at = now()

        # Reopening clears the current resolution.
        if new_status == "Under Review":
            self.resolution = ""

        if new_status == "Resolved":
            self.resolution = resolution

        self.status = new_status

    #  Convert the incident to the shared schema
    def to_dict(self):
        return {
            field: getattr(self, field)
            for field in INCIDENT_FIELDS
        }


#  Manage incidents and generate unique IDs
class IncidentManager:
    def __init__(self, incidents=None, actions=None):
        self.incidents = list(incidents) if incidents is not None else []
        self.actions = list(actions) if actions is not None else []

        # Validate loaded incidents and prevent duplicate IDs
        used_ids = set()

        for incident in self.incidents:
            incident.validate()

            if incident.incident_id in used_ids:
                raise ValueError(
                    "Duplicate incident ID: " + incident.incident_id
                )

            used_ids.add(incident.incident_id)

        # Validate action IDs and prevent duplicates
        used_action_ids = set()

        for action in self.actions:
            if not isinstance(action, dict):
                raise ValueError("Each action must be a dictionary.")

            action_id = action.get("action_id")

            if (
                not isinstance(action_id, str)
                or not action_id.startswith("ACT-")
                or not action_id[4:].isdecimal()
            ):
                raise ValueError(
                    "Each action needs an ID like ACT-0001."
                )

            if action_id in used_action_ids:
                raise ValueError(
                    "Duplicate action ID: " + action_id
                )

            used_action_ids.add(action_id)

    # Generate the next incident ID
    def _next_incident_id(self):
        if not self.incidents:
            return "INC-1001"

        biggest = max(
            int(incident.incident_id[4:])
            for incident in self.incidents
        )

        return "INC-" + str(biggest + 1)

    # Generate the next action ID
    def _next_action_id(self):
        if not self.actions:
            return "ACT-0001"

        biggest = max(
            int(action["action_id"][4:])
            for action in self.actions
        )

        return "ACT-" + str(biggest + 1).zfill(4)

    # Requirement 5: Create a new incident.
    def add_incident(self, report_data):
        if not isinstance(report_data, dict):
            raise ValueError("Report data must be a dictionary.")

        required_fields = (
            "category",
            "description",
            "severity",
            "urgency",
            "affected_scope",
        )

        for field in required_fields:
            if field not in report_data:
                raise ValueError(
                    "Missing required field: " + field
                )

        description = report_data["description"]

        if isinstance(description, str):
            description = description.strip()

        incident = Incident(
            incident_id=self._next_incident_id(),
            reported_at=now(),
            category=report_data["category"],
            description=description,
            severity=report_data["severity"],
            urgency=report_data["urgency"],
            affected_scope=report_data["affected_scope"],
            priority_score=0,
        )

        incident.priority_score = incident.calculate_priority()
        incident.validate()

        self.incidents.append(incident)
        return incident

    # Find an incident by ID
    def find_incident(self, incident_id):
        if not isinstance(incident_id, str) or not incident_id.strip():
            return None

        incident_id = incident_id.strip()

        for incident in self.incidents:
            if incident.incident_id == incident_id:
                return incident

        return None

    # Update status and record the action.
    def update_status(
        self,
        incident_id,
        new_status,
        note="",
        resolution="",
    ):
        incident = self.find_incident(incident_id)

        if incident is None:
            raise ValueError("Incident was not found.")

        if not isinstance(note, str):
            raise ValueError("Action note must be text.")

        # Save the previous values before changing the incident
        old_status = incident.status
        old_resolution = incident.resolution

        # This validates the transition before changing the status
        incident.update_status(new_status, resolution)

        note = note.strip()

        # Preserve the previous resolution in the action history
        if old_status == "Resolved" and new_status == "Under Review":
            previous_resolution = (
                "Previous resolution: " + old_resolution
            )

            note = (
                note + "\n" + previous_resolution
                if note
                else "Reopened. " + previous_resolution
            )

        action = {
            "action_id": self._next_action_id(),
            "incident_id": incident.incident_id,
            "action_type": (
                "Status changed: "
                + old_status
                + " -> "
                + new_status
            ),
            "action_time": now(),
            "note": note,
        }

        self.actions.append(action)
        return incident