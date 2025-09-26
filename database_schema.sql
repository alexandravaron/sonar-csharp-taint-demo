-- SonarQube C# Taint Analysis Demo - Database Schema
-- This schema supports the vulnerable demo application
-- DO NOT USE IN PRODUCTION - FOR DEMONSTRATION ONLY

-- Users table
CREATE TABLE Users (
    Id int PRIMARY KEY IDENTITY(1,1),
    Username nvarchar(50) NOT NULL,
    Email nvarchar(100) NOT NULL,
    FirstName nvarchar(50),
    LastName nvarchar(50),
    Role nvarchar(20) DEFAULT 'User',
    Category nvarchar(20) DEFAULT 'general',
    Active bit DEFAULT 1,
    CreatedAt datetime2 DEFAULT GETDATE()
);

-- Audit Log table for logging import actions
CREATE TABLE AuditLog (
    Id int PRIMARY KEY IDENTITY(1,1),
    Message nvarchar(max),
    Timestamp datetime2 DEFAULT GETDATE()
);

-- Authentication Log table
CREATE TABLE AuthLog (
    Id int PRIMARY KEY IDENTITY(1,1),
    Username nvarchar(50),
    Domain nvarchar(50),
    Success bit,
    Timestamp datetime2 DEFAULT GETDATE()
);

-- Search Log table
CREATE TABLE SearchLog (
    Id int PRIMARY KEY IDENTITY(1,1),
    SearchFilter nvarchar(500),
    Domain nvarchar(50),
    ResultCount int,
    Timestamp datetime2 DEFAULT GETDATE()
);

-- Error Log table
CREATE TABLE ErrorLog (
    Id int PRIMARY KEY IDENTITY(1,1),
    Message nvarchar(max),
    Timestamp datetime2 DEFAULT GETDATE()
);

-- Password Rules table for complexity checking
CREATE TABLE PasswordRules (
    Id int PRIMARY KEY IDENTITY(1,1),
    Username nvarchar(50),
    RestrictedPasswords nvarchar(max),
    CreatedAt datetime2 DEFAULT GETDATE()
);

-- Password History table
CREATE TABLE PasswordHistory (
    Id int PRIMARY KEY IDENTITY(1,1),
    Username nvarchar(50),
    PasswordHash nvarchar(256),
    CreatedAt datetime2 DEFAULT GETDATE()
);

-- Sample data for testing
INSERT INTO Users (Username, Email, FirstName, LastName, Role, Category) VALUES
('john.doe', 'john.doe@example.com', 'John', 'Doe', 'User', 'general'),
('jane.admin', 'jane.admin@example.com', 'Jane', 'Admin', 'Administrator', 'admin'),
('bob.user', 'bob.user@example.com', 'Bob', 'User', 'User', 'general'),
('alice.dev', 'alice.dev@example.com', 'Alice', 'Developer', 'Developer', 'technical');

INSERT INTO PasswordRules (Username, RestrictedPasswords) VALUES
('john.doe', 'password,123456,admin'),
('jane.admin', 'admin,root,password123');

-- Note: This schema is designed to be vulnerable to SQL injection
-- when used with the demo application's unsafe query construction
