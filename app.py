import os
from flask import Flask,jsonify,request #importing flaask instance
from flask_sqlalchemy import SQLAlchemy #importing sql alchemy
from flask_migrate import Migrate
from sqlalchemy_serializer import SerializerMixin
from dotenv import load_dotenv
from flask_cors import CORS
from sqlalchemy import func
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from datetime import datetime
from marshmallow import Schema, fields
from flask_bcrypt import Bcrypt

load_dotenv()
app = Flask(__name__) #creating an insatnce of flask app
CORS(app, supports_credentials=True, origins="http://localhost:5173")



DB_CONFIG = {
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT'),
    'database': os.getenv('DB_NAME'),
}

app.config['SQLALCHEMY_DATABASE_URI']=app.config['SQLALCHEMY_DATABASE_URI']=f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
app.config['SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
db = SQLAlchemy(app)#linking sqlalchemy to db
bcrypt = Bcrypt(app)
migrate = Migrate(app,db) #initialise migration
jwt = JWTManager(app)


#models
class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(400), nullable=False)

    orders = db.relationship("Order", back_populates="user", cascade="all, delete-orphan", single_parent=True)
    carts = db.relationship("Cart", back_populates="user", cascade="all, delete-orphan", single_parent=True)

    serialize_rules = ('-orders.user', '-carts.user','-password',)

    def generate_token(self):
        return create_access_token(identity=self.id)

class UserSchema(Schema):
    id = fields.Int()
    name = fields.Str()
    email = fields.Email()
    role = fields.Str()



class Product(db.Model, SerializerMixin):
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(250), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)

    orders = db.relationship("Order", back_populates="product", cascade="all, delete-orphan", single_parent=True)
    carts = db.relationship("Cart", back_populates="product", cascade="all, delete-orphan", single_parent=True)

    serialize_rules = ('-orders.product', '-carts.product',)

class ProductSchema(Schema):
    id = fields.Int()
    name = fields.Str()
    description = fields.Str()
    price = fields.Float()
    image = fields.Str()
    category = fields.Str()
    location = fields.Str()


class Order(db.Model, SerializerMixin):
    __tablename__ = "orders"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User", back_populates="orders", single_parent=True)
    product = db.relationship("Product", back_populates="orders", single_parent=True)

    serialize_rules = ('-user.orders', '-product.orders',)

class OrderSchema(Schema):
    id = fields.Int()
    product_id = fields.Int()
    quantity = fields.Int()
    status = fields.Str()
    created_at = fields.DateTime()
    user_id = fields.Int()


class Cart(db.Model, SerializerMixin):
    __tablename__ = "cart"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    user = db.relationship("User", back_populates="carts", single_parent=True)
    product = db.relationship("Product", back_populates="carts", single_parent=True)

    serialize_rules = ('-user.carts', '-product.carts',)

class CartSchema(Schema):
    id = fields.Int()
    product_id = fields.Int()
    quantity = fields.Int()
    user_id = fields.Int()





@app.route('/', methods=['GET'])
def index():
    return jsonify({'message': 'Hello World!'}),200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Missing email or password', 'error': True}), 400
    if '@' not in email or '.' not in email:
        return jsonify({'message': 'Invalid email format', 'error': True}), 400

    user = User.query.filter(func.lower(User.email) == func.lower(email)).first()
    if not user:
        return jsonify({'message': 'User not found, please sign up', 'error': True}), 404

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid password', 'error': True}), 401

    # Generate JWT access token
    access_token = create_access_token(identity={'id': user.id, 'role': user.role})

    return jsonify({
        'message': 'Login successful',
        'user': {'id': user.id, 'name': user.name, 'email': user.email, 'role': user.role},
        'access_token': access_token
    }), 200


@app.route('/signup', methods=['POST'])
def create_user():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    role = data.get('role')
    password = data.get('password')

    if not all([name, email, role, password]):
        return jsonify({'message': 'Missing required fields', 'error': True}), 400

    if not '@' in email or not '.' in email:
        return jsonify({'message': 'Invalid email format', 'error': True}), 400

    if not isinstance(role, str):
        return jsonify({'message': 'Role must be a string', 'error': True}), 400

    if len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters', 'error': True}), 400

    existing_user = User.query.filter(func.lower(User.email) == func.lower(email)).first()
    if existing_user:
        return jsonify({'message': 'Email already exists', 'error': True}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, email=email, role=role, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully', 'error': False}), 201

@app.route('/create-order', methods=['POST'])#create an order
@jwt_required()
def create_order():
    data = request.get_json()
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    
    product_id = data.get('product_id')
    quantity = data.get('quantity')
    status = data.get('status')
    created_at = datetime.now()


    new_order = Order(user_id=user_id, product_id=product_id, quantity=quantity, status=status, created_at=created_at)
    db.session.add(new_order)
    db.session.commit()
    return jsonify({'message': 'Order created successfully'}), 201

@app.route('/products', methods=['GET'])#get all the products
def get_products():
    products = Product.query.all()
    schema = ProductSchema(many=True)
    return jsonify(schema.dump(products)),200

@app.route('/products/<int:product_id>', methods=['GET'])#get a specific product
def get_product(product_id):
    product = Product.query.filter_by(id=product_id).first()
    if product is None:
        return jsonify({"error": "Product not found"}), 404
    schema = ProductSchema()
    return jsonify(schema.dump(product)), 200

@app.route('/products/<string:category>', methods=['GET'])#get products by category
def get_product_by_category(category):
    products = Product.query.filter_by(category = category).all()
    Schema = ProductSchema(many=True)
    return jsonify(Schema.dump(products)),200

@app.route('/products/<string:location>', methods=['GET'])#get products by location
def get_product_by_location(location):
    products = Product.query.filterfilter(func.lower(Product.location) == func.lower(location)).all()
    schema = ProductSchema(many=True)
    return jsonify(schema.dump(products)),200

@app.route('/cart', methods=['GET'])
@jwt_required()
def get_cart():
    # Get the current user's identity from the JWT
    current_user_id = get_jwt_identity()  # The payload should contain user ID or username
    
    # Query the user's cart from the database
    user_cart = Cart.query.filter_by(user_id=current_user_id).first()
    
    if user_cart:
        return jsonify({"cart": user_cart.items}), 200
    return jsonify({"message": "No cart found"}), 404




######admin routes#######
@app.route('/admin/orders', methods=['GET'])#get all the orders
@jwt_required()
def get_orders():
    orders = Order.query.all()
    schema = OrderSchema(many=True)
    return jsonify(schema.dump(orders)),200

@app.route('/admin/users', methods=['GET'])#get all the users
@jwt_required()
def get_users():
    users = User.query.all()
    schema = UserSchema(many=True)
    return jsonify(schema.dump(users)), 200

@app.route('/admin/product', methods=['POST'])#create a new product
@jwt_required()
def add_product():
    data = request.get_json()
    name = data.get('name')
    category = data.get('category')
    location = data.get('location')
    price = data.get('price')
    image = data.get('image')
    description = data.get('description')
    if not name or not category or not location or not price:
        return jsonify({'message': 'Missing required fields'}), 400
    if not isinstance(category, str):
        return jsonify({'message': 'Category must be a string'}), 400
    if not isinstance(location, str):
        return jsonify({'message': 'Location must be a string'}), 400
    if not isinstance(price, int):
        return jsonify({'message': 'Price must be an integer'}), 400
    
    new_product = Product(name=name,description=description,image=image, category=category, location=location, price=price)
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product created successfully'}), 201

#delete a product
@app.route('/admin/product/<int:product_id>', methods=['DELETE', 'OPTIONS'])
@jwt_required()
def delete_product(product_id):
    if request.method == 'OPTIONS':
        return '', 200  #Handle preflight request
     
    product = Product.query.filter_by(id=product_id).first()
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'}), 200

#update a product
@app.route('/admin/product/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    product = Product.query.filter_by(id=product_id).first()
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    data = request.get_json()
    product.name = data.get('name')
    product.description = data.get('description')
    product.image = data.get('image')
    product.category = data.get('category')
    product.location = data.get('location')
    product.price = data.get('price')
    db.session.commit()
    return jsonify({'message': 'Product updated successfully'}), 200

#update_order
@app.route('/admin/orders/<int:order_id>', methods=['PUT'])
@jwt_required()
def update_order(order_id):
    order = Order.query.filter_by(id=order_id).first()
    if not order:
        return jsonify({'message': 'Order not found'}), 404
    data = request.get_json()
    order.status = data.get('status')
    db.session.commit()
    return jsonify({'message': 'Order updated successfully'}), 200

#delete an order
@app.route('/admin/orders/<int:order_id>', methods=['DELETE'])
@jwt_required()
def delete_order(order_id):
    order = Order.query.filter_by(id=order_id).first()
    if not order:
        return jsonify({'message': 'Order not found'}), 404
    db.session.delete(order)
    db.session.commit()
    return jsonify({'message': 'Order deleted successfully'}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Get port from environment, default to 5000
    app.run(debug=False, host='0.0.0.0', port=port)
