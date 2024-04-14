#!/usr/bin/env python3
from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from config import app, db, api
from models import User, Recipe
import bcrypt

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        # Check if username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {'error': 'Username already taken'}, 422

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create a new user
        new_user = User(
            username=username,
            _password_hash=hashed_password.decode('utf-8'),
            image_url=image_url,
            bio=bio
        )
        db.session.add(new_user)
        db.session.commit()

        # Save the user's ID in the session
        session['user_id'] = new_user.id

        return {
            'id': new_user.id,
            'username': new_user.username,
            'image_url': new_user.image_url,
            'bio': new_user.bio
        }, 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            return {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }, 200
        else:
            return {'error': 'User is not logged in'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user._password_hash.encode('utf-8')):
            session['user_id'] = user.id
            return {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }, 200
        else:
            return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        if user_id:
            session.pop('user_id', None)
            return {}, 204
        else:
            return {'error': 'User is not logged in'}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            recipes = Recipe.query.all()
            recipe_data = [
                {
                    'title': recipe.title,
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': {
                        'id': recipe.user.id,
                        'username': recipe.user.username,
                        'image_url': recipe.user.image_url,
                        'bio': recipe.user.bio
                    }
                }
                for recipe in recipes
            ]
            return {'recipes': recipe_data}, 200
        else:
            return {'error': 'User is not logged in'}, 401

    def post(self):
        user_id = session.get('user_id')
        if user_id:
            data = request.get_json()
            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')

            # Validate the recipe data
            if not title or not instructions or not minutes_to_complete:
                return {'error': 'Missing required fields'}, 422
            if len(instructions) < 50:
                return {'error': 'Instructions must be at least 50 characters'}, 422

            # Create a new recipe
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )
            db.session.add(new_recipe)
            db.session.commit()

            return {
                'title': new_recipe.title,
                'instructions': new_recipe.instructions,
                'minutes_to_complete': new_recipe.minutes_to_complete,
                'user': {
                    'id': new_recipe.user.id,
                    'username': new_recipe.user.username,
                    'image_url': new_recipe.user.image_url,
                    'bio': new_recipe.user.bio
                }
            }, 201
        else:
            return {'error': 'User is not logged in'}, 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)