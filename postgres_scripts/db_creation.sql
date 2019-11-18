\set ON_ERROR_STOP on
CREATE DATABASE emles_oauth2;
CREATE DATABASE emles_oauth2_test;

\c emles_oauth2

drop table if exists oauth_client_token CASCADE;
create table oauth_client_token (
  token_id VARCHAR(255),
  token BYTEA,
  authentication_id VARCHAR(255),
  user_name VARCHAR(255),
  client_id VARCHAR(255)
);
drop table if exists oauth_client_details CASCADE;
CREATE TABLE oauth_client_details (
  client_id varchar(255) NOT NULL,
  resource_ids varchar(255) DEFAULT NULL,
  client_secret varchar(255) DEFAULT NULL,
  scope varchar(255) DEFAULT NULL,
  authorized_grant_types varchar(255) DEFAULT NULL,
  web_server_redirect_uri varchar(255) DEFAULT NULL,
  authorities varchar(255) DEFAULT NULL,
  access_token_validity integer DEFAULT NULL,
  refresh_token_validity integer DEFAULT NULL,
  additional_information varchar(255) DEFAULT NULL,
  autoapprove varchar(255) DEFAULT NULL
);
drop table if exists oauth_access_token CASCADE;
create table oauth_access_token (
  token_id VARCHAR(255),
  token BYTEA,
  authentication_id VARCHAR(255),
  user_name VARCHAR(255),
  client_id VARCHAR(255),
  authentication BYTEA,
  refresh_token VARCHAR(255)
);
drop table if exists oauth_refresh_token CASCADE;
create table oauth_refresh_token(
  token_id VARCHAR(255),
  token BYTEA,
  authentication BYTEA
);
drop table if exists authority CASCADE;
CREATE TABLE authority (
  id  serial,
  authority varchar(255),
  primary key (id)
);
drop table if exists app_user CASCADE;

CREATE TABLE app_user (
  user_id  SERIAL not null,
  enabled BOOLEAN not null,
  name varchar(255) not null,
  password varchar(255) not null,
  version integer,
  last_password_reset_date TIMESTAMP DEFAULT Now(),
  email VARCHAR(255) not null,
  phone VARCHAR(255) not null,
  primary key (user_id)
);
drop table if exists app_user_authorities CASCADE;
CREATE TABLE app_user_authorities (
  app_user_user_id bigint not null,
  authorities_id bigint not null
);
drop table if exists oauth_code CASCADE;
create table oauth_code (
  code VARCHAR(255), authentication BYTEA
);
drop table if exists oauth_approvals CASCADE;
create table oauth_approvals (
    userId VARCHAR(255),
    clientId VARCHAR(255),
    scope VARCHAR(255),
    status VARCHAR(10),
    expiresAt TIMESTAMP(0),
    lastModifiedAt TIMESTAMP(0)
);

drop table if exists password_reset_token CASCADE;
create table password_reset_token (
  id serial not null,
  user_id integer not null,
  expiry_date TIMESTAMP not null,
  token VARCHAR(255) not null,
  primary key (id)
);

drop table if exists account_activation_token CASCADE;
create table account_activation_token (
  id serial not null,
  user_id integer not null,
  token VARCHAR(255) not null,
  primary key (id)
);

ALTER TABLE password_reset_token
    ADD CONSTRAINT user_id FOREIGN KEY (user_id) REFERENCES app_user(user_id);

ALTER TABLE account_activation_token
    ADD CONSTRAINT user_id FOREIGN KEY (user_id) REFERENCES app_user(user_id);  

DROP TABLE IF EXISTS customer CASCADE;
CREATE TABLE customer (
    customer_id serial NOT NULL,
    customer_name text[] NOT NULL,
    customer_phone text[],
    customer_address text[]
);

DROP TABLE IF EXISTS orders CASCADE;
CREATE TABLE orders (
    order_id serial NOT NULL,
    order_date date NOT NULL,
    customer_id integer NOT NULL,
    app_user_id integer NOT NULL
);

DROP TABLE IF EXISTS order_detail CASCADE;
CREATE TABLE order_detail (
    order_detail_id serial NOT NULL,
    order_id integer NOT NULL,
    product_id integer NOT NULL,
    quantity integer NOT NULL
);

DROP TABLE IF EXISTS product CASCADE;
CREATE TABLE product (
    product_id serial NOT NULL,
    product_name text NOT NULL,
    product_price numeric(10,2) NOT NULL,
    product_quantity_left integer NOT NULL
);


ALTER TABLE customer
    ADD CONSTRAINT customer_pkey PRIMARY KEY (customer_id);


ALTER TABLE ONLY order_detail
    ADD CONSTRAINT order_detail_pkey PRIMARY KEY (order_detail_id);


ALTER TABLE orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (order_id);


ALTER TABLE product
    ADD CONSTRAINT product_pkey PRIMARY KEY (product_id);


ALTER TABLE orders
    ADD CONSTRAINT customer_id FOREIGN KEY (customer_id) REFERENCES customer(customer_id);


ALTER TABLE order_detail
    ADD CONSTRAINT order_id FOREIGN KEY (order_id) REFERENCES orders(order_id);


ALTER TABLE order_detail
    ADD CONSTRAINT product_id FOREIGN KEY (product_id) REFERENCES product(product_id);


ALTER TABLE orders
    ADD CONSTRAINT app_user_id FOREIGN KEY (app_user_id) REFERENCES app_user(user_id);

INSERT INTO authority  VALUES(1,'ROLE_OAUTH_ADMIN');
INSERT INTO authority VALUES(2,'ROLE_USER');
INSERT INTO authority VALUES(3,'ROLE_PRODUCT_ADMIN');
INSERT INTO app_user (enabled, name, password, version, last_password_reset_date, email, phone) VALUES(TRUE,'oauth_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0', now(), 'oauth_admin@emles.com', '700700700');
INSERT INTO app_user (enabled, name, password, version, last_password_reset_date, email, phone) VALUES(TRUE,'resource_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0', now(), 'resource_admin@emles.com', '700799799');
INSERT INTO app_user (enabled, name, password, version, last_password_reset_date, email, phone) VALUES(TRUE,'product_admin','$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2','0', now(), 'product_admin@emles.com', '700800800');
INSERT INTO app_user_authorities VALUES (1,1);
INSERT INTO app_user_authorities VALUES (2,2);
INSERT INTO app_user_authorities VALUES (3,3);


INSERT INTO oauth_client_details VALUES('curl_client','product_api', '$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2', 'read,write', 'password', 'http://127.0.0.1', 'ROLE_PRODUCT_ADMIN', 7200, 0, NULL, 'true');
INSERT INTO oauth_client_details VALUES('oauth_client_id','oauth_server_api', '$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2', 'read,write', 'password', 'http://127.0.0.1', 'ROLE_OAUTH_ADMIN', 7200, 0, NULL, 'true');
INSERT INTO product (product_id, product_name,  product_price, product_quantity_left) VALUES (1, 'SOS', 9.99, 10);
INSERT INTO product (product_id, product_name,  product_price, product_quantity_left) VALUES (2, 'SOS 1', 9.99, 10);

\c emles_oauth2_test
drop table if exists oauth_client_token CASCADE;
create table oauth_client_token (
  token_id VARCHAR(255),
  token BYTEA,
  authentication_id VARCHAR(255),
  user_name VARCHAR(255),
  client_id VARCHAR(255)
);
drop table if exists oauth_client_details CASCADE;
CREATE TABLE oauth_client_details (
  client_id varchar(255) NOT NULL,
  resource_ids varchar(255) DEFAULT NULL,
  client_secret varchar(255) DEFAULT NULL,
  scope varchar(255) DEFAULT NULL,
  authorized_grant_types varchar(255) DEFAULT NULL,
  web_server_redirect_uri varchar(255) DEFAULT NULL,
  authorities varchar(255) DEFAULT NULL,
  access_token_validity integer DEFAULT NULL,
  refresh_token_validity integer DEFAULT NULL,
  additional_information varchar(255) DEFAULT NULL,
  autoapprove varchar(255) DEFAULT NULL
);
drop table if exists oauth_access_token CASCADE;
create table oauth_access_token (
  token_id VARCHAR(255),
  token BYTEA,
  authentication_id VARCHAR(255),
  user_name VARCHAR(255),
  client_id VARCHAR(255),
  authentication BYTEA,
  refresh_token VARCHAR(255)
);
drop table if exists oauth_refresh_token CASCADE;
create table oauth_refresh_token(
  token_id VARCHAR(255),
  token BYTEA,
  authentication BYTEA
);
drop table if exists authority CASCADE;
CREATE TABLE authority (
  id  serial,
  authority varchar(255),
  primary key (id)
);
drop table if exists app_user CASCADE;

CREATE TABLE app_user (
  user_id  SERIAL not null,
  enabled BOOLEAN not null,
  name varchar(255) not null,
  password varchar(255) not null,
  version integer,
  last_password_reset_date TIMESTAMP DEFAULT Now(),
  email VARCHAR(255) not null,
  phone VARCHAR(255) not null,
  primary key (user_id)
);
drop table if exists app_user_authorities CASCADE;
CREATE TABLE app_user_authorities (
  app_user_user_id bigint not null,
  authorities_id bigint not null
);
drop table if exists oauth_code CASCADE;
create table oauth_code (
  code VARCHAR(255), authentication BYTEA
);
drop table if exists oauth_approvals CASCADE;
create table oauth_approvals (
    userId VARCHAR(255),
    clientId VARCHAR(255),
    scope VARCHAR(255),
    status VARCHAR(10),
    expiresAt TIMESTAMP(0),
    lastModifiedAt TIMESTAMP(0)
);

drop table if exists password_reset_token CASCADE;
create table password_reset_token (
  id serial not null,
  user_id integer not null,
  expiry_date TIMESTAMP not null,
  token VARCHAR(255) not null,
  primary key (id)
);

drop table if exists account_activation_token CASCADE;
create table account_activation_token (
  id serial not null,
  user_id integer not null,
  token VARCHAR(255) not null,
  primary key (id)
);

ALTER TABLE password_reset_token
    ADD CONSTRAINT user_id FOREIGN KEY (user_id) REFERENCES app_user(user_id);

ALTER TABLE account_activation_token
    ADD CONSTRAINT user_id FOREIGN KEY (user_id) REFERENCES app_user(user_id);  

DROP TABLE IF EXISTS customer CASCADE;
CREATE TABLE customer (
    customer_id serial NOT NULL,
    customer_name text[] NOT NULL,
    customer_phone text[],
    customer_address text[]
);

DROP TABLE IF EXISTS orders CASCADE;
CREATE TABLE orders (
    order_id serial NOT NULL,
    order_date date NOT NULL,
    customer_id integer NOT NULL,
    app_user_id integer NOT NULL
);

DROP TABLE IF EXISTS order_detail CASCADE;
CREATE TABLE order_detail (
    order_detail_id serial NOT NULL,
    order_id integer NOT NULL,
    product_id integer NOT NULL,
    quantity integer NOT NULL
);

DROP TABLE IF EXISTS product CASCADE;
CREATE TABLE product (
    product_id serial NOT NULL,
    product_name text NOT NULL,
    product_price numeric(10,2) NOT NULL,
    product_quantity_left integer NOT NULL
);


ALTER TABLE customer
    ADD CONSTRAINT customer_pkey PRIMARY KEY (customer_id);


ALTER TABLE ONLY order_detail
    ADD CONSTRAINT order_detail_pkey PRIMARY KEY (order_detail_id);


ALTER TABLE orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (order_id);


ALTER TABLE product
    ADD CONSTRAINT product_pkey PRIMARY KEY (product_id);


ALTER TABLE orders
    ADD CONSTRAINT customer_id FOREIGN KEY (customer_id) REFERENCES customer(customer_id);


ALTER TABLE order_detail
    ADD CONSTRAINT order_id FOREIGN KEY (order_id) REFERENCES orders(order_id);


ALTER TABLE order_detail
    ADD CONSTRAINT product_id FOREIGN KEY (product_id) REFERENCES product(product_id);


ALTER TABLE orders
    ADD CONSTRAINT app_user_id FOREIGN KEY (app_user_id) REFERENCES app_user(user_id);


INSERT INTO product (product_id, product_name,  product_price, product_quantity_left) VALUES (1, 'SOS', 9.99, 10);
INSERT INTO product (product_id, product_name,  product_price, product_quantity_left) VALUES (2, 'SOS 1', 9.99, 10);

\unset ON_ERROR_STOP