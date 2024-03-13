from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "secret"

users_db = {}
orders_db = {}
users_db['admin'] = {'password': generate_password_hash('admin'), 'profile_image': None}


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and check_password_hash(users_db.get(username, {}).get('password', ''), password):
            session['admin'] = True
            return redirect(url_for('admin'))
        elif username in users_db and check_password_hash(users_db[username]['password'], password):
            session['username'] = username
            return redirect(url_for('profile'))
        else:
            return render_template('login.html', users_db=users_db, orders_db=orders_db,
                                   message='Neplatné jméno nebo heslo.')
    return render_template('login.html', orders_db=orders_db, users_db=users_db)


# Odhlášení
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('admin', None)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        if username in users_db:
            return render_template('register.html', message='Uživatel již existuje.')
        else:
            users_db[username] = {'password': generate_password_hash(request.form['password']),
                                  'profile_image': None}
            session['username'] = username
            return redirect(url_for('profile'))
    return render_template('register.html')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' in session:
        username = session['username']
        if request.method == 'POST':
            # Změna hesla
            if 'new_password' in request.form:
                new_password = generate_password_hash(request.form['new_password'])
                users_db[username]['password'] = new_password
                return redirect(url_for('profile'))
            # Přidání objednávky
            elif 'order_message' in request.form:
                message = request.form['order_message']
                show_message = 'show_message' in request.form
                orders_db[username] = {'message': message, 'show_message': show_message}
                return redirect(url_for('profile'))
            # Zrušení objednávky
            elif 'cancel_order' in request.form:
                if username in orders_db:
                    del orders_db[username]
                    return redirect(url_for('profile'))
        return render_template('profile.html', username=username, orders_db=orders_db, users_db=users_db)
    else:
        return redirect(url_for('login'))


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'admin' in session and session['admin']:
        if request.method == 'POST':
            if 'username' in request.form:
                username = request.form['username']
                if username in users_db and username != 'admin':
                    del users_db[username]
                    if username in orders_db:
                        del orders_db[username]
                else:
                    return render_template('admin.html', users_db=users_db, message='Nelze smazat admina.')
            elif 'delete_order' in request.form:
                username = request.form['delete_order']
                if username in orders_db:
                    del orders_db[username]
                    return redirect(url_for('admin'))
        return render_template('admin.html', orders_db=orders_db, users_db=users_db)
    else:
        return redirect(url_for('login'))


@app.route('/admin/change_password', methods=['POST'])
def change_admin_password():
    if 'admin' in session and session['admin']:
        if 'new_password' in request.form:
            new_password = generate_password_hash(request.form['new_password'])
            users_db['admin']['password'] = new_password
    return redirect(url_for('admin'))


@app.route('/users')
def users():
    return render_template('users.html', users_db=users_db)


if __name__ == '__main__':
    app.run(debug=True)
