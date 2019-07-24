DELETE FROM authority;
DELETE FROM credentials;
DELETE FROM credentials_authorities;
DELETE FROM oauth_client_details;

INSERT INTO authority  VALUES(1,'ROLE_OAUTH_ADMIN');
INSERT INTO authority VALUES(2,'ROLE_RESOURCE_ADMIN');
INSERT INTO authority VALUES(3,'ROLE_PRODUCT_ADMIN');
INSERT INTO credentials VALUES(1,TRUE,'oauth_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0');
INSERT INTO credentials VALUES(2,TRUE,'resource_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0');
INSERT INTO credentials  VALUES(3,TRUE,'product_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0');
INSERT INTO credentials_authorities VALUES (1,1);
INSERT INTO credentials_authorities VALUES (2,2);
INSERT INTO credentials_authorities VALUES (3,3);


INSERT INTO oauth_client_details VALUES('integration_test_product_admin','oauth_server_api', '$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2', 'read,write', 'refresh_token,password', 'http://127.0.0.1', 'ROLE_PRODUCT_ADMIN', 1800, 3600, NULL, 'true');

INSERT INTO oauth_client_details VALUES('integration_test_oauth_admin','oauth_server_api', '$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2', 'read,write', 'password', 'http://127.0.0.1', 'ROLE_OAUTH_ADMIN', 30, 0, NULL, 'true');

INSERT INTO oauth_client_details VALUES('integration_test_resource_admin','oauth_server_api', '$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2', 'read,write', 'refresh_token,password', 'http://127.0.0.1', 'ROLE_RESOURCE_ADMIN', 30, 60, NULL, 'true');
