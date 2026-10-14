import json
from datetime import datetime
#articls
class Article:
    def __init__(self, article_id, title, category, summary, content, source_name="", source_url="", published_at=None):
        self.article_id = article_id
        self.title = title
        self.category = category
        self.summary = summary
        self.content = content
        self.source_name = source_name
        self.source_url = source_url
        self.published_at = published_at or str(datetime.now().date())

    def get_dict(self):
        return {
            "article_id": self.article_id,
            "title": self.title,
            "category": self.category,
            "summary": self.summary,
            "content": self.content,
            "source_name": self.source_name,
            "source_url": self.source_url,
            "published_at": self.published_at
        }

class ArticleService:

    def __init__(self, articles=None):
        self.articles = articles or []

    def add_article(self, article: Article):
        self.articles.append(article)

    def get_all_articles(self):
        return self.articles

    def get_article_by_id(self, article_id):
        for article in self.articles:
            if article.article_id == article_id:
                return article
        return None

    def search_articles(self, keyword):
        keyword = keyword.lower()
        return [
            a for a in self.articles 
            if keyword in a.title.lower() or keyword in a.summary.lower() or keyword in a.content.lower()
        ]

    def get_by_category(self, category):
    
        if not category or category == "All":
            return self.articles
        return [a for a in self.articles if a.category.lower() == category.lower()]

#quiz
class QuizQuestion:
    def __init__(self, question_id, topic, question, options, correct_option, explanation=""):
        self.question_id = question_id
        self.topic = topic
        self.question = question
        self.options = options          
        self.correct_option = correct_option  
        self.explanation = explanation 

class QuizResult:
    def __init__(self, result_id, participant_code, quiz_stage, score, total_questions, quiz_date=None):
        self.result_id = result_id
        self.participant_code = participant_code
        self.quiz_stage = quiz_stage
        self.score = score
        self.total_questions = total_questions
        self.quiz_date = quiz_date or str(datetime.now().date())

    def get_dict(self):
        return {
            "result_id": self.result_id,
            "participant_code": self.participant_code,
            "quiz_stage": self.quiz_stage,
            "score": self.score,
            "total_questions": self.total_questions,
            "quiz_date": self.quiz_date
        }

class QuizService:
    def __init__(self, questions=None):
        self.questions = questions or []

    def add_question(self, question: QuizQuestion):
        self.questions.append(question)

    def get_questions_by_topic(self, topic):
        if not topic or topic == "All":
            return self.questions
        return [q for q in self.questions if q.topic.lower() == topic.lower()]

    def calculate_score(self, user_answers: dict):
        
        score = 0
        total = len(self.questions)
        feedback_details = []

        for q in self.questions:
            user_ans = user_answers.get(q.question_id)
            is_correct = (user_ans == q.correct_option)
            if is_correct:
                score += 1
            
            feedback_details.append({
                "question_id": q.question_id,
                "question": q.question,
                "user_answer": user_ans,
                "correct_option": q.correct_option,
                "is_correct": is_correct,
                "explanation": q.explanation
            })

        return {
            "score": score,
            "total_questions": total,
            "percentage": (score / total) * 100 if total > 0 else 0,
            "feedback": feedback_details
        }