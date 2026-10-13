# CyberAware - Member 1: Core Incident Management

This is the core incident part of the CyberAware project (SIC 8 graduation project).
It stores incident reports, checks them, gives each one a preliminary priority score, and controls how the status changes.
It only organizes reports. It does not scan messages or confirm that an attack happened.

## Files

| File | What it is |
|---|---|
| `member1_incident_core.py` | The code: `Incident` class and `IncidentManager` |
| `README.md` | This file |

## What we used

| Tool | Where | Why |
|---|---|---|
| Python 3.7 or newer | everything | The project language. Tested on Python 3.12 |
| `dataclasses` (standard library) | `Incident` | Gives the class its fields without writing `__init__` |
| `datetime` (standard library) | dates and times | Create the current time and check the date format |
| `unittest` (standard library) | tests | Run the tests, no install needed |
| Mermaid | `MEMBER1_DOCUMENTATION.md` | Workflow diagrams (GitHub shows them as pictures) |

No extra packages are needed, so there is nothing to install.

Programming ideas used:
- **OOP:** the `Incident` class holds one report; `IncidentManager` manages the list of reports and actions.
- **Validation:** `validate()` rejects wrong or missing values with a clear `ValueError`.
- **Allowed transitions:** a dictionary (`STATUS_TRANSITIONS`) says which status can follow which.
- **Data types:** tuples for fixed lists of allowed values, a dictionary for transitions and reports, a set to find duplicate IDs, and lists to keep incidents and actions.

## How to run the tests

Put both `.py` files in the same folder, then:

```
python -m unittest -v test_member1_incident_core
```

All tests should pass (`OK`).

## Quick example

```python
from member1_incident_core import IncidentManager

manager = IncidentManager()

incident = manager.add_incident({
    "category": "Phishing / Suspicious Message",
    "description": "A simulated message asked me to verify my account.",
    "severity": "High",
    "urgency": "Medium",
    "affected_scope": "One user",
})
print(incident.incident_id, incident.priority_score, incident.status)
# INC-1001 5 Submitted

manager.update_status("INC-1001", "Under Review", note="Started review.")
manager.update_status("INC-1001", "Resolved", resolution="Password reset.")
print(manager.actions[0]["action_id"])
# ACT-0001

try:
    manager.update_status("INC-1001", "Submitted")
except ValueError as error:
    print("Error:", error)
# Error: Status cannot change from Resolved to Submitted.
```

## Main rules

- **Priority score** = severity points + urgency points, from 2 to 7 (Low = 1, Medium = 2, High = 3, Critical = 4; urgency has no Critical). Example: High + Medium = 5.
- **Status changes:** Submitted -> Under Review -> Resolved or Closed. A Resolved report can be Closed or reopened (back to Under Review). Closed is final.
- A report must be reviewed before it is resolved or closed. Resolving needs a resolution text.
- Reopening clears the resolution; the old text is kept in the note of the action record.
- Every status change saves an action record (`ACT-0001`, `ACT-0002`, ...). A rejected change saves nothing.
- IDs: incidents `INC-1001`, `INC-1002`, ... and actions `ACT-0001`, ... New IDs use the biggest existing number + 1.
- Dates: `DD/MM/YYYY HH:MM AM/PM`, for example `12/10/2026 10:30 AM`.
- Description: not empty, up to 1000 characters.
- Every error is a `ValueError` with a clear message.

The full tables and diagrams are in `MEMBER1_DOCUMENTATION.md`.

## Notes for the other members

- Dates are text, so convert them before sorting or analysing, for example `pd.to_datetime(column, format="%d/%m/%Y %I:%M %p")`.
- Loading from CSV: `priority_score` must be an `int` and blank cells must be `""`, not NaN.
- This module keeps data in memory only. Saving and loading files is the job of Member 4 (`DataRepository`); use `to_dict()`, `INCIDENT_FIELDS`, `ACTION_FIELDS`, `manager.incidents` and `manager.actions`.
- Algorithms (queue, stack, sorting, searching) are Member 2. Streamlit pages are Member 5.

## Limits

- Data is lost when the program closes unless another module saves it.
- No login or user roles (outside the MVP scope in the system design).
- Dates are saved to the minute only.
