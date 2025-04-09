from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import traceback

app = Flask(__name__)
app.config['SECRET_KEY'] = '63f4945d921d599f27ae4fdf5bada3f1'  # В продакшене использовать безопасный ключ
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///padlet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Обработчик ошибок для API
@app.errorhandler(500)
def handle_500_error(e):
    if request.is_json:
        return jsonify({
            'error': 'Internal Server Error',
            'message': str(e)
        }), 500
    return render_template('error.html', error=e), 500

@app.errorhandler(404)
def handle_404_error(e):
    if request.is_json:
        return jsonify({
            'error': 'Not Found',
            'message': str(e)
        }), 404
    return render_template('error.html', error=e), 404

@app.errorhandler(403)
def handle_403_error(e):
    if request.is_json:
        return jsonify({
            'error': 'Forbidden',
            'message': str(e)
        }), 403
    return render_template('error.html', error=e), 403

# Модели данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    boards = db.relationship('Board', backref='owner', lazy=True)
    shared_boards = db.relationship('BoardShare', backref='user', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    boards = db.relationship('Board', backref='category', lazy=True)

class Board(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    posts = db.relationship('Post', backref='board', lazy=True)
    shared_with = db.relationship('BoardShare', backref='board', lazy=True)

class BoardShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    board_id = db.Column(db.Integer, db.ForeignKey('board.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    can_edit = db.Column(db.Boolean, default=False)
    can_comment = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    board_id = db.Column(db.Integer, db.ForeignKey('board.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='posts')
    comments = db.relationship('Comment', backref='post', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='comments')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Маршруты аутентификации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'danger')
            return redirect(url_for('register'))
            
        user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('index'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
            
        flash('Неверное имя пользователя или пароль', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Основные маршруты
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/boards')
@login_required
def boards():
    search = request.args.get('search', '')
    category_id = request.args.get('category')
    sort_by = request.args.get('sort', 'created_at')
    
    query = Board.query.filter(
        (Board.user_id == current_user.id) |
        (Board.shared_with.any(BoardShare.user_id == current_user.id))
    )
    
    if search:
        query = query.filter(Board.title.ilike(f'%{search}%'))
    if category_id:
        query = query.filter(Board.category_id == category_id)
        
    if sort_by == 'title':
        query = query.order_by(Board.title)
    elif sort_by == 'updated_at':
        query = query.order_by(Board.updated_at.desc())
    else:
        query = query.order_by(Board.created_at.desc())
        
    boards = query.all()
    categories = Category.query.all()
    
    return render_template('boards.html', boards=boards, categories=categories)

@app.route('/board/create', methods=['GET', 'POST'])
@login_required
def create_board():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category_id = request.form.get('category_id')
        
        board = Board(
            title=title,
            description=description,
            category_id=category_id,
            user_id=current_user.id
        )
        db.session.add(board)
        db.session.commit()
        return redirect(url_for('view_board', board_id=board.id))
        
    categories = Category.query.all()
    return render_template('create_board.html', categories=categories)

@app.route('/board/<int:board_id>')
def view_board(board_id):
    board = Board.query.get_or_404(board_id)
    # Проверяем, есть ли у пользователя доступ к доске
    has_access = False
    can_edit = False
    can_comment = False
    if current_user.is_authenticated:
        has_access = (board.user_id == current_user.id or 
                     any(share.user_id == current_user.id for share in board.shared_with))
        can_edit = (board.user_id == current_user.id or 
                   any(share.user_id == current_user.id and share.can_edit for share in board.shared_with))
        can_comment = (board.user_id == current_user.id or 
                      any(share.user_id == current_user.id and share.can_comment for share in board.shared_with))
        
        # Отладочная информация
        print(f"User: {current_user.username}")
        print(f"Board owner: {board.user_id}")
        print(f"Has access: {has_access}")
        print(f"Can edit: {can_edit}")
        print(f"Can comment: {can_comment}")
        print("Shared with:")
        for share in board.shared_with:
            print(f"- User {share.user.username}: edit={share.can_edit}, comment={share.can_comment}")
    
    if not has_access:
        flash('У вас нет доступа к этой доске', 'danger')
        return redirect(url_for('boards'))
    return render_template('board.html', board=board, can_edit=can_edit, can_comment=can_comment)

@app.route('/board/<int:board_id>/share', methods=['POST'])
@login_required
def share_board(board_id):
    try:
        board = Board.query.get_or_404(board_id)
        if board.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        username = request.form.get('username')
        can_edit = request.form.get('can_edit', 'false') == 'true'
        can_comment = request.form.get('can_comment', 'true') == 'true'
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        # Проверяем, не существует ли уже шаринг для этого пользователя
        existing_share = BoardShare.query.filter_by(
            board_id=board_id,
            user_id=user.id
        ).first()
        
        if existing_share:
            # Обновляем существующие права
            existing_share.can_edit = can_edit
            existing_share.can_comment = can_comment
        else:
            # Создаем новый шаринг
            share = BoardShare(
                board_id=board_id,
                user_id=user.id,
                can_edit=can_edit,
                can_comment=can_comment
            )
            db.session.add(share)
            
        db.session.commit()
        return jsonify({'message': 'Board shared successfully'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error sharing board: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@app.route('/board/<int:board_id>/unshare/<int:user_id>', methods=['POST'])
@login_required
def unshare_board(board_id, user_id):
    try:
        board = Board.query.get_or_404(board_id)
        if board.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        share = BoardShare.query.filter_by(
            board_id=board_id,
            user_id=user_id
        ).first()
        
        if share:
            db.session.delete(share)
            db.session.commit()
            return jsonify({'message': 'Board unshared successfully'})
        return jsonify({'error': 'Share not found'}), 404
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error unsharing board: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

# API маршруты
@app.route('/api/posts', methods=['POST'])
@login_required
def create_post():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        content = data.get('content')
        board_id = data.get('board_id')
        
        if not content or not board_id:
            return jsonify({'error': 'Missing required fields'}), 400
            
        board = Board.query.get_or_404(board_id)
        # Проверяем права на редактирование
        can_edit = (board.user_id == current_user.id or 
                   any(share.user_id == current_user.id and share.can_edit for share in board.shared_with))
        
        if not can_edit:
            return jsonify({'error': 'Unauthorized'}), 403
            
        post = Post(
            content=content,
            board_id=board_id,
            user_id=current_user.id
        )
        db.session.add(post)
        db.session.commit()
        
        return jsonify({
            'message': 'Post created successfully',
            'post': {
                'id': post.id,
                'content': post.content,
                'created_at': post.created_at.isoformat(),
                'user': post.user.username
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating post: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@app.route('/api/posts/<int:post_id>', methods=['PUT', 'DELETE'])
@login_required
def manage_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        board = post.board
        
        # Проверяем права на редактирование
        can_edit = (board.user_id == current_user.id or 
                   any(share.user_id == current_user.id and share.can_edit for share in board.shared_with))
        
        if not can_edit:
            return jsonify({'error': 'Unauthorized'}), 403
            
        if request.method == 'PUT':
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            post.content = data.get('content', post.content)
            db.session.commit()
            return jsonify({'message': 'Post updated successfully'})
            
        elif request.method == 'DELETE':
            db.session.delete(post)
            db.session.commit()
            return jsonify({'message': 'Post deleted successfully'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error managing post: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@app.route('/api/posts/<int:post_id>/comments', methods=['POST'])
@login_required
def create_comment(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        board = post.board
        
        # Проверяем права на комментирование
        can_comment = (board.user_id == current_user.id or 
                      any(share.user_id == current_user.id and share.can_comment for share in board.shared_with))
        
        if not can_comment:
            return jsonify({'error': 'У вас нет прав на комментирование'}), 403
            
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        content = data.get('content')
        if not content:
            return jsonify({'error': 'Missing content'}), 400
            
        comment = Comment(
            content=content,
            post_id=post_id,
            user_id=current_user.id
        )
        db.session.add(comment)
        db.session.commit()
        
        return jsonify({
            'message': 'Comment created successfully',
            'comment': {
                'id': comment.id,
                'content': comment.content,
                'created_at': comment.created_at.isoformat(),
                'user': comment.user.username
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating comment: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

def init_db():
    with app.app_context():
        db.create_all()
        # Создаем базовые категории, если их нет
        if not Category.query.first():
            categories = [
                Category(name='Личное'),
                Category(name='Работа'),
                Category(name='Учеба'),
                Category(name='Проекты'),
                Category(name='Другое')
            ]
            for category in categories:
                db.session.add(category)
            db.session.commit()
        print("База данных успешно инициализирована!")

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 