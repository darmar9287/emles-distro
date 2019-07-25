INSERT INTO authority  VALUES(1,'ROLE_OAUTH_ADMIN');
INSERT INTO authority VALUES(2,'ROLE_RESOURCE_ADMIN');
INSERT INTO authority VALUES(3,'ROLE_PRODUCT_ADMIN');
INSERT INTO app_user VALUES(1,TRUE,'oauth_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0');
INSERT INTO app_user VALUES(2,TRUE,'resource_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0');
INSERT INTO app_user  VALUES(3,TRUE,'product_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0');
INSERT INTO app_user_authorities VALUES (1,1);
INSERT INTO app_user_authorities VALUES (2,2);
INSERT INTO app_user_authorities VALUES (3,3);


INSERT INTO oauth_client_details VALUES('curl_client','product_api', '$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2', 'read,write', 'password', 'http://127.0.0.1', 'ROLE_PRODUCT_ADMIN', 7200, 0, NULL, 'true');
INSERT INTO oauth_client_details VALUES('curl_client','oauth_server_api', '$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2', 'read,write', 'password', 'http://127.0.0.1', 'ROLE_PRODUCT_ADMIN', 7200, 0, NULL, 'true');