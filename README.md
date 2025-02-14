# Memo Board API with Go and PostgreSQL

This project is a RESTful API built with Go (Golang) and uses PostgreSQL as its database for storing and managing data. The database is named `memo_board`, and the API provides endpoints for managing memos, such as creating, reading, updating, and deleting memos.

## Requirements

- Go (version 1.18 or higher)
- PostgreSQL (version 13 or higher)
- DBeaver (for managing the PostgreSQL database)

## Setup Database 

### 1. Create the memo_board Database
If you're running PostgreSQL locally, you must create the memo_board database. You can do this using DBeaver or via the PostgreSQL CLI.

Using DBeaver:

1. Open DBeaver and connect to your PostgreSQL server.
2. Right-click on your PostgreSQL connection and select SQL Editor.
3. Run the following SQL query to create the memo_board database:

```
CREATE DATABASE memo_board;
```

4. Once the database is created, you can connect by selecting the memo_board database from the DBeaver UI.
Import Database using Dump File

You can restore it using DBeaver by using .sql dump from this link https://drive.google.com/file/d/1Y5MA3mBREC0LFFwMedBhRcJRfSAmloky/view?usp=sharing and downloading the file:

1. Right-click on the memo_board database in DBeaver and select Tools -> Restore.
2. In the Restore dialog, select the .sql dump file that contains the schema and data for the database.
3. Click Start to begin the restore process.
4. Wait for DBeaver to complete the process, and the data will be imported into the memo_board database.

## Setup Instructions

### 1. Clone the repository

Clone the repository to your local machine:

```
git clone https://github.com/KanisphonKonhirungit/memo_board_api
```

### 2. Install Go dependencies
Navigate into the project directory and install the Go dependencies:

```
cd memo-board-api
go mod tidy
```

### 3. Configure Database Connection
In the project directory line 137, create a .env file to store your database connection details.

```
connStr := "user=postgres password=1234 dbname=memo_board host=localhost port=5433 sslmode=disable"
```

Make sure to replace the database credentials with the correct values for your environment.

### 4. Run the API
Once the database is set up, you can run the Go API. To start the API server, use the following command:

```
go run main.go
```
The API server will start running on http://localhost:8080.
