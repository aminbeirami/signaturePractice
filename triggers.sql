DELIMITER #
trigger for the users table
CREATE TRIGGER insert_user AFTER INSERT ON users
FOR EACH ROW BEGIN
INSERT INTO events(event, table_name, event_time) VALUES ('insert','users',DEFAULT);
END; #

-- trigger for the messages table
CREATE TRIGGER insert_message AFTER INSERT ON messages
FOR EACH ROW BEGIN
SET @user = NEW.user;
SET @message = NEW.message;
SET @signature = NEW.signature;
SET @table = 'messages';
SET @action = 'I';
INSERT INTO events(event, table_name, event_time, message, signature, user) 
VALUES (@action, @table, DEFAULT, @message, @signature, @user);
END; #

CREATE TRIGGER update_message AFTER UPDATE ON messages
FOR EACH ROW BEGIN
SET @user = NEW.user;
SET @message = NEW.message;
SET @signature = NEW.signature;
SET @table = 'messages';
SET @action = 'U';
INSERT INTO events(event, table_name, event_time, message, signature, user) 
VALUES (@action, @table, DEFAULT, @message, @signature, @user);
END; #

DELIMITER ;

