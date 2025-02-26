from flask import Flask, render_template, request, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'movies_db'
app.config['SECRET_KEY'] = 'your_secret_key'

mysql = MySQL(app)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith("Bearer "):
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            token = token.split()[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            cur = mysql.connection.cursor()
            cur.execute("SELECT id, username FROM users WHERE id = %s", (data['user_id'],))
            user = cur.fetchone()
            cur.close()
            if not user:
                return jsonify({'message': 'User not found!'}), 403
            return f(user, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 403
    return decorated

@app.route('/')
def login_page():
    return render_template('index.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/movies')
def movies_page():
    return render_template('movies.html')

@app.route('/review')
def review_page():
    return render_template('review.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'])
    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (data['username'], data['email'], hashed_password))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True, 'message': 'User registered successfully'})
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, password FROM users WHERE username = %s", (data['username'],))
    user = cur.fetchone()
    cur.close()
    if user and check_password_hash(user[1], data['password']):
        token = jwt.encode({'user_id': user[0], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                           app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/movies/<int:movie_id>', methods=['GET'])
@token_required
def get_movie(user, movie_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, title, year, genre, image_url FROM movies WHERE id = %s", (movie_id,))
    movie = cur.fetchone()
    cur.close()

    if not movie:
        print("Movie not found!")  # Debugging
        return jsonify({"error": "Movie not found"}), 404

    return jsonify({
        "id": movie[0],
        "title": movie[1],
        "year": movie[2],
        "genre": movie[3],
        "image_url": movie[4]
    })

@app.route('/api/movies', methods=['GET'])
def get_movies():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, title, year, genre, image_url FROM movies")
    movies = cur.fetchall()
    cur.close()

    if not movies:
        return jsonify({"message": "No movies found"}), 404

    return jsonify([
        {"id": m[0], "title": m[1], "year": m[2], "genre": m[3], "image_url": m[4]}
        for m in movies
    ])

@app.route('/api/user', methods=['GET'])
@token_required
def get_user(user):
    return jsonify({"username": user[1]})

@app.route('/api/reviews', methods=['GET'])
def get_reviews():
    movie_id = request.args.get("movie_id")
    if not movie_id:
        return jsonify({"error": "Missing movie_id"}), 400

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT reviews.id, reviews.rating, reviews.review_text, users.username 
        FROM reviews 
        JOIN users ON reviews.user_id = users.id 
        WHERE reviews.movie_id = %s
    """, (movie_id,))
    
    reviews = cur.fetchall()
    cur.close()
    
    return jsonify([{ "id": r[0], "rating": r[1], "review_text": r[2], "username": r[3] } for r in reviews])

@app.route('/api/reviews', methods=['POST'])
@token_required
def submit_review(user):
    data = request.get_json()
    if not data.get('movie_id') or not data.get('review_text') or not data.get('rating'):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO reviews (movie_id, user_id, rating, review_text) VALUES (%s, %s, %s, %s)",
                    (data['movie_id'], user[0], data['rating'], data['review_text']))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Review submitted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/reviews/<int:review_id>", methods=["PUT"])
@token_required
def edit_review(user, review_id):
    data = request.get_json()
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id FROM reviews WHERE id = %s", (review_id,))
    review = cur.fetchone()

    if not review:
        return jsonify({"message": "Review not found"}), 404
    if review[0] != user[0]:
        return jsonify({"message": "You can only edit your own review"}), 403

    cur.execute("UPDATE reviews SET review_text = %s, rating = %s WHERE id = %s",
                (data.get("review_text"), data.get("rating"), review_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({"message": "Review updated successfully"}), 200

@app.route("/api/reviews/<int:review_id>", methods=["DELETE"])
@token_required
def delete_review(user, review_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id FROM reviews WHERE id = %s", (review_id,))
    review = cur.fetchone()

    if not review:
        return jsonify({"message": "Review not found"}), 404
    if review[0] != user[0]:
        return jsonify({"message": "You can only delete your own review"}), 403

    cur.execute("DELETE FROM reviews WHERE id = %s", (review_id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({"message": "Review deleted successfully"}), 200

@app.route('/api/movies', methods=['GET'])
@token_required
def get_all_movies(user):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, title, year, genre, image_url FROM movies")
    movies = cur.fetchall()
    cur.close()

    print("Fetched movies:", movies)  # Debugging line

    if not movies:
        return jsonify([])  # Return an empty list instead of 404

    return jsonify([
        {
            "id": movie[0],
            "title": movie[1],
            "year": movie[2],
            "genre": movie[3],
            "image_url": movie[4]
        }
        for movie in movies
    ])

if __name__ == '__main__':
    app.run(debug=True)
