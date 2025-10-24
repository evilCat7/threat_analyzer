CREATE TABLE reports (
    id INTEGER PRIMARY KEY,
    url TEXT,
    timestamp TEXT
);

CREATE TABLE vulns (
    id INTEGER PRIMARY KEY,
    type TEXT,
    description TEXT,
    report_id INTEGER,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
);