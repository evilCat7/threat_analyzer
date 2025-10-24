# Threat Analyzer

## Description:

In a few words, this is a command-line tool that helps you find vulnerabilities in Web Applications.

I always been fascinated with cybersecurity and pentesting since to defend and understand the attacks to a software, one has to understand the threatened application in a good level of detail, and I've always liked tinkering and trying to understand software.

This console application was my attempt to aid developers in findings vulnerabilities in their web apps,
or at least the very obvious mistakes that can go unnoticed. It was not made to be tested without the website owner's consent.
It's not "millitary grade" by any means, more like a very simple scanner with some nice command-line interface and
a way to storing and reviewing the previous scans reports in a database.

Together with the application, I made very simple vulnerable web page called "buggy_app". It's purpose is to be comically vulnerable to
common web attacks like Cross Site Scripting  and SQL Injections. That way I could see if the project was working as intended and also
I could practice some TDD concepts I was learning as I was developing this project. I used the Pytest lib to help me config and run the tests.

The test files are in the src/test folder and the tested app is in the buggy_app folder, the test_scanner.py file is the
main test script that does a full test and two smaller tests to determine if the threat_analyzer class, which is where the application's core logic is coded, works as expected. In the full test I use the url of website also made deliberately unsafe called Juice Shop made by
OWASP.

In order to automate the process of exposing the vulnerable web app in localhost path and running the tests against it,
I used a feature in pytest called "fixtures" that allowed a script like the one in the project called conftest.py
that runs before or after the actual test are triggered, so is to set up all the necessary conditions for the test.

To test, run the following command in the project root:

```console
pytest 
```

Simple, right?

Now to the main application functionality.

To run the app, first run:

```console
pip install requirements.txt
```

So is to install all the dependencies.

The main ones are:

requests
beautifulsoup4
urllib3
These are for the scanner logic

colorama
rich
These are for the cli ui

flask
This one is for the test app to work

Now you'll need to set up the database:

Make sure you have sqlite3 installed, then run:

```console
sqlite3 vulns.db < database/vulns.sql
```

This sql script creates the application's database and sets up the two tables called reports and vulns.

Now you can run the actual application with:

```console
python src/main.py
```

Functionality:
After that you'll be greeted with a lovely ascii art courtesy of [https://patorjk.com/software/taag/](https://patorjk.com/software/taag/)
And the main menus presenting two options:
1 - Run test
or
2 - Access records

Let's discuss the "Run test" option, since it is the main functionality of the application.
Upon selection, the user is prompted to give the URL of a website on the internet.
Then the application will trigger the scanner and display information about which vulnerabilities it could find,
as well as save in the records the full report of this scan.

Now if the user wants to see the result of previous scans, he/she can select the second option, "Access records".
Upon selection, there will be another menu with the options
1 - Last Scan
2 - Find a Report
3 - Clean Data

The first option simply displays the informationn of the last scan made.

The second conducts a search in the database for specific report.
The user is prompted to give either of three options an id, url or timestamp of the record they want to see.
The application automatically identify if the answer is one the options and search the database and prints the corresponding record.

The third option just cleans the database, I wanted to include this option because it felt to me that it makes more sense to
wipe the database and start over then to remove reports individually.

Implementation details:
The code can be separated in two main logical components the core and ui folders

In the "core" resides the main application class called "ThreatAnalyzer" in the file "threat_analyzer.py", this is the scanner logic.
It receives two arguments the url of the website being tested and the max depth that the scanner will crawl within this url (default = 3)

It has a init method to set up class state, a method to normalize the url and one to crawl and store the websites paths.
But the main method is called "scan"
using multithreading this method takes all urls discovered by the crawl method and pass them to methods that the will perform
detection and reporting of various vulnerabilities.
these methods are:
check_sql_injection, checks for sql injections in url query paremeters.
check_xss, checks for xss triggered in url query paremeters.
check_sensitive_info, checks if the website leaks information like phone number, email, etc.
check_forms, checks if the submit forms in the webpage itself are vulnerable to xss and sqli.

It uses the BeautifulSoup, requests and urllib to handle more easily the requests to the webpages and parsing of html content.

It is inspired on this script: [https://www.freecodecamp.org/news/build-a-web-application-security-scanner-with-python/](https://www.freecodecamp.org/news/build-a-web-application-security-scanner-with-python/)
But it was heavly altered by me to support the database integration and the method check_forms was added and built from scratch.

In the "ui" folder resides the applications user interface logic, as well as the most interaction to the database.
The main file here is "cli.py", where we have the whole interface logic segmented in three functions:
print_welcome_art, it simply prints the nice ascii art in the beginning, it made sense to separate it from the rest of the logic.

cli, now this is the main user controlled flow, in here we have the menus and the whole logic of selecting inputs and query the database.

display_report, receives report information and display it neatly on the screen.

classify_input, it is used in the second menu when the user asks to see a specific report, it handles all the logic of parsing the user input to then set up the database query correctly, I'm very proud of this function it felt cool writing it!

Now there's a database folder and in retrospect I could have made the whole database querying logic separated from the cli logic. But when
I thought about that I was already pretty far in the project and it felt like over engineering something that could be simple, any way it's a good idea if the application had growed any bigger it could have become a necessity!

To finish, I think it's worth explaining why there is two implementations of the cli functions.
The first one is done by me and the second is the rework that ChatGPT made to make the ui prettier! I think it's more honest to include both, Both works but the ChatGPT one was more pleasant to see so the applicaton is shipped with it.

I had a lot fun writing this app, as well as the whole CS50 course! I learned so much!!!
And it's great that you guys made all this effort to make such high quality content available freely on the internet. Thank you!

Resources:

Web scanner in python: https://www.freecodecamp.org/news/build-a-web-application-security-scanner-with-python/

ASCII art generator: https://patorjk.com/software/taag/

Vulnerable application for ethical testing: https://juice-shop.herokuapp.com/