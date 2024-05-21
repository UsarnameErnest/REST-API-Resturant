from flask import Flask, request

from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import JWTManager, jwt_required, current_user, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
# Change this to a secure secret key in production
app.config['SECRET_KEY'] = 'super-secret-key'
# Change this to a secure JWT secret key in production
app.config['JWT_SECRET_KEY'] = 'jwt-super-secret-key'
api = Api(app)
jwt = JWTManager(app)

# Sample data for users
users = [
    {
        'id': 1, 'name': 'Frog', 'email': 'frogo@example.com',
        'password': generate_password_hash('my password'), 'role': 'customer'
    },
    {
        'id': 2, 'name': 'AdminUser', 'email': 'admin@example.com',
        'password': generate_password_hash('admin password'), 'role': 'admin'
    }
]

# Sample data for dishes and ratings
dishes = [
    {'id': 1, 'name': 'HobbitStew', 'description': 'A hearty stew from the Shire',
        'price': 12.99, 'image': 'hobbit_stew.jpg'},
    # Add more sample dishes as needed
]

ratings = [
    {'user_id': 1, 'dish_id': 1, 'rating': 4},
    # Add more sample ratings as needed
]


# User authentication functions
def authenticate(email, password):
    user = next((user for user in users if user['email'] == email), None)
    if user and check_password_hash(user['password'], password):
        return user


#def identity(payload):
  #  user_id = payload['identity']
    #return next((user for user in users if user['id'] == user_id), None)


# Extend Flask-JWT-Extended to handle roles
@jwt.additional_claims_loader
def add_claims_to_access_token(identity):
    return {'role': identity['role']}

# for loading user details in a protected route


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data['sub']['id']
    return next((user for user in users if user['id'] == identity), None)


# Resource for logging in
class Login(Resource):
    def post(self):
        # get user provided login details
        email = request.json.get('email', None)
        password = request.json.get('password', None)

        user = next((user for user in users if user['email'] == email), None)
        # check if the user exists & password is not empty and is valid
        if user and password and check_password_hash(user['password'], password):
            return {'token': create_access_token(identity=user)}
        else:
            return {"msg": "Bad username or password"}, 401


# Resource to register a new user
class RegisterUser(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True,
                            help='Name cannot be blank')
        parser.add_argument('email', type=str, required=True,
                            help='Email cannot be blank')
        parser.add_argument('password', type=str, required=True,
                            help='Password cannot be blank')
        args = parser.parse_args()

        # Check if the user with the given email already exists
        if any(user['email'] == args['email'] for user in users):
            return {'message': 'User with this email already exists'}, 400

        # Create a new user
        new_user = {
            'id': len(users) + 1,
            'name': args['name'],
            'email': args['email'],
            'password': generate_password_hash(args['password']),
            'role': 'customer'  # Default role for new users
        }
        users.append(new_user)
        return {'message': 'User created successfully'}, 201


# Resource to get user details (requires authentication)
class UserDetails(Resource):
    @jwt_required()
    def get(self):
        return {
            'id': current_user['id'],
            'name': current_user['name'],
            'email': current_user['email'],
            'role': current_user['role']
        }


# Resource to create, view, list, update, and delete dishes (admin only)
class AdminDishResource(Resource):
    @jwt_required()
    def get(self, dish_id=None):
        if dish_id:
            dish = next(
                (dish for dish in dishes if dish['id'] == dish_id), None
            )
            if dish:
                return {'dish': dish}
            else:
                return {'message': 'Dish not found'}, 404
        else:
            return {'dishes': dishes}

    @jwt_required()
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True,
                            help='Name cannot be blank')
        parser.add_argument('description', type=str,
                            required=True, help='Description cannot be blank')
        parser.add_argument('price', type=float, required=True,
                            help='Price cannot be blank')
        parser.add_argument('image', type=str, required=True,
                            help='Image URL cannot be blank')
        args = parser.parse_args()

        new_dish = {
            'id': len(dishes) + 1,
            'name': args['name'],
            'description': args['description'],
            'price': args['price'],
            'image': args['image']
        }
        dishes.append(new_dish)
        return {'message': 'Dish created successfully'}, 201

    @jwt_required()
    def patch(self, dish_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True,
                            help='Name cannot be blank')
        parser.add_argument('description', type=str,
                            required=True, help='Description cannot be blank')
        parser.add_argument('price', type=float, required=True,
                            help='Price cannot be blank')
        parser.add_argument('image', type=str, required=True,
                            help='Image URL cannot be blank')
        args = parser.parse_args()

        dish = next((dish for dish in dishes if dish['id'] == dish_id), None)
        if dish:
            dish.update({
                'name': args['name'],
                'description': args['description'],
                'price': args['price'],
                'image': args['image']
            })
            return {'message': 'Dish updated successfully'}
        else:
            return {'message': 'Dish not found'}, 404

    @jwt_required()
    def delete(self, dish_id): 
        global dishes
        dishes = [dish for dish in dishes if dish['id']!=dish_id]
        return {'message ': 'Dish deleted successfully'}


# Resource to search,view,and rate dishes(customer only)
class CustomerDishResource(Resource):
    @jwt_required(['customer'])
    def get(self, dish_id=None):
        if dish_id:
            dish = next(
                (dish for dish in dishes if dish['id'] == dish_id), None
            )
            if dish:
                return {'dish': dish}
            else:
                return {'message': 'Dish not found'}, 404
        else:
            return {'dishes': dishes}

    @jwt_required()
    def post(self, dish_id=None):
        # do not continue if dish_id to be rated is not provided
        if not dish_id:
            return {'message': 'provide dish_id to be rated'}
        parser = reqparse.RequestParser()
        parser.add_argument(
            'rating', type=int, required=True, help='Rating cannot be blank'
        )
        args = parser.parse_args()

        # Check if the customer has already rated the dish
        user_id = current_user['id']
        existing_rating = next((
            rating for rating in ratings if rating['user_id'] == user_id and rating['dish_id'] == dish_id
        ), None)
        if existing_rating:
            existing_rating['rating'] = args['rating']
            return {'message': 'Product rating updated successfully'}, 200
        else:
            ratings.append({
                'user_id': user_id, 'dish_id': dish_id, 'rating': args['rating']
            })
            return {'message': 'Product rated successfully'}, 200


api.add_resource(
    AdminDishResource, '/admin_dishes/', '/admin_dishes/<int:dish_id>'
)
api.add_resource(
    CustomerDishResource, '/customer_dishes/', '/customer_dishes/<int:dish_id>/'
)
api.add_resource(RegisterUser, '/register/')
api.add_resource(Login, '/login/')
api.add_resource(UserDetails, '/user/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)