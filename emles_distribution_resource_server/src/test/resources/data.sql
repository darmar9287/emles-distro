DELETE FROM authority;
DELETE FROM app_user;
DELETE FROM app_user_authorities;
DELETE FROM oauth_client_details;
DELETE FROM product;

INSERT INTO authority  VALUES(1,'ROLE_OAUTH_ADMIN');
INSERT INTO authority VALUES(2,'ROLE_USER');
INSERT INTO authority VALUES(3,'ROLE_PRODUCT_ADMIN');
INSERT INTO app_user (enabled, name, password, version, last_password_reset_date, email, phone) VALUES(TRUE,'oauth_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0', now(), 'oauth_admin@emles.com', '700700700');
INSERT INTO app_user (enabled, name, password, version, last_password_reset_date, email, phone) VALUES(TRUE,'resource_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0', now(), 'resource_admin@emles.com', '700799799');
INSERT INTO app_user (enabled, name, password, version, last_password_reset_date, email, phone) VALUES(TRUE,'product_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0', now(), 'product_admin@emles.com', '700800800');
INSERT INTO app_user_authorities VALUES (4,1);
INSERT INTO app_user_authorities VALUES (5,2);
INSERT INTO app_user_authorities VALUES (6,3);


INSERT INTO oauth_client_details VALUES('curl_client','product_api', '$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2', 'read,write', 'password', 'http://127.0.0.1', 'ROLE_PRODUCT_ADMIN', 7200, 0, NULL, 'true');

INSERT INTO product (product_id, product_name,  product_price, product_quantity_left) VALUES (1, 'SOS', 9.99, 10);
INSERT INTO product (product_id, product_name,  product_price, product_quantity_left) VALUES (2, 'SOS 1', 9.99, 10);
