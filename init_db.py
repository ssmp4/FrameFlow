from flask_app import app, db, Category

def init_database():
    with app.app_context():
        # Создаем все таблицы
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
        else:
            print("База данных уже инициализирована!")

if __name__ == '__main__':
    init_database() 