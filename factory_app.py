from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'factorysecret'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost/factory_tracker'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

STAGES = ['Подготовка', 'Сборка', 'Контроль качества', 'Упаковка']
ADMINS = ['factory_admin@tracker.local']

class User(db.Model):
    __tablename__ = 'factory_users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Task(db.Model):
    __tablename__ = 'factory_tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    stage = db.Column(db.String(50), nullable=False, default='Подготовка')
    author_email = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class History(db.Model):
    __tablename__ = 'factory_history'
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, nullable=False)
    stage = db.Column(db.String(50), nullable=False)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('factory_login'))
        return f(*args, **kwargs)
    return wrapped

@app.route('/')
def index():
    return redirect(url_for('factory_dashboard'))

@app.route('/factory_register', methods=['GET', 'POST'])
def factory_register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(email=email).first():
            flash('Пользователь уже существует')
            return redirect(url_for('factory_register'))
        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация успешна')
        return redirect(url_for('factory_login'))
    return render_template('factory_register.html')

@app.route('/factory_login', methods=['GET', 'POST'])
def factory_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_email'] = email
            session['is_admin'] = email in ADMINS
            return redirect(url_for('factory_dashboard'))
        flash('Неверный логин или пароль')
    return render_template('factory_login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('factory_login'))

@app.route('/factory_dashboard')
@login_required
def factory_dashboard():
    stage_filter = request.args.get('stage')
    is_admin = session.get('is_admin')

    if is_admin:
        query = Task.query
        if stage_filter:
            query = query.filter_by(stage=stage_filter)
        tasks = query.order_by(Task.created_at.desc()).all()

        # Общая статистика для админа
        stage_counts = {stage: Task.query.filter_by(stage=stage).count() for stage in STAGES}
        delayed_tasks = Task.query.filter(Task.created_at < datetime.utcnow() - timedelta(days=3)).all()
    else:
        # Пользователь видит только свои задачи
        tasks = Task.query.filter_by(author_email=session['user_email']).order_by(Task.created_at.desc()).all()
        stage_counts = {stage: Task.query.filter_by(stage=stage, author_email=session['user_email']).count() for stage in STAGES}
        delayed_tasks = Task.query.filter(
            Task.created_at < datetime.utcnow() - timedelta(days=3),
            Task.author_email == session['user_email']
        ).all()

    return render_template('factory_dashboard.html',
                           tasks=tasks,
                           stages=STAGES,
                           is_admin=is_admin,
                           stage_counts=stage_counts,
                           delayed_tasks=delayed_tasks)

@app.route('/factory_create_task', methods=['GET', 'POST'])
@login_required
def factory_create_task():
    if request.method == 'POST':
        title = request.form['title']
        task = Task(title=title, stage='Подготовка', author_email=session['user_email'])
        db.session.add(task)
        db.session.commit()
        db.session.add(History(task_id=task.id, stage='Подготовка'))
        db.session.commit()
        return redirect(url_for('factory_dashboard'))
    return render_template('factory_create_task.html')

@app.route('/next_stage/<int:task_id>')
@login_required
def next_stage(task_id):
    if not session.get('is_admin'):
        flash('Нет доступа')
        return redirect(url_for('factory_dashboard'))
    task = Task.query.get_or_404(task_id)
    idx = STAGES.index(task.stage)
    if idx < len(STAGES) - 1:
        task.stage = STAGES[idx + 1]
        db.session.add(History(task_id=task.id, stage=task.stage))
        db.session.commit()
    return redirect(url_for('factory_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
