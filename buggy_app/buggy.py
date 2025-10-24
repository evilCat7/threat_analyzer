from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    name_display = ""
    error = ""
    if request.method == "POST":
        name = request.form.get("name", "")
        phone = request.form.get("phone", "")
        # XSS VULNERABLE: Direct insertion without escaping
        name_display = f"<h2>Hello {name}, your number is {phone}!</h2>"

        # SQLI VULNERABLE: 
        with sqlite3.connect("db.sqlite3") as conn:
            try:
                cursor = conn.cursor()
                cursor.execute(f"INSERT INTO users(name, phone_number) VALUES ('{name}', '{phone}');")
                conn.commit()
            except Exception as e:
               error = f"<h2>{e}</h2>"


    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Buggy App</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
            }}
            .container {{
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                max-width: 400px;
                width: 100%;
            }}
            .form-card {{
                background: rgba(255, 255, 255, 0.95);
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                width: 100%;
                margin-bottom: 20px;
            }}
            .form-title {{
                font-size: 24px;
                font-weight: 600;
                color: #333;
                margin-bottom: 20px;
                text-align: center;
            }}
            .form-group {{
                margin-bottom: 20px;
            }}
            .form-group label {{
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: #555;
            }}
            .form-group input {{
                width: 100%;
                padding: 12px 16px;
                border: 2px solid #e1e5e9;
                border-radius: 8px;
                font-size: 16px;
                background: white;
            }}
            .btn {{
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
            }}
            .result {{
                background: rgba(255, 255, 255, 0.95);
                padding: 20px;
                border-radius: 15px;
                text-align: center;
                width: 100%;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="form-card">
                <h2 class="form-title"> Enter your information</h2>
                <form method="post">
                    <div class="form-group">
                        <label for="name">Your Name</label>
                        <input type="text" id="name" name="name" required>
                        <label for="name">Your Phone Number</label>
                        <input type="text" id="phone" name="phone" required>
                    </div>
                    <button type="submit" class="btn">Get a free hello!</button>
                </form>
            </div>
            {name_display}
            {error}
        </div>
    </body>
    </html>
    '''



if __name__ == '__main__':
    app.run(debug=True)