from flask_wtf import FlaskForm
from wtforms import SubmitField, PasswordField, validators
from wtforms.validators import DataRequired, Length, Regexp

class passwordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(12, 128), Regexp('^[a-zA-Z0-9-_@$!%*?&]+$')])
    confirm = PasswordField(validators=[validators.EqualTo('password', 'Password mismatch')])
    submit = SubmitField('Submit')