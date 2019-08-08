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
  id  integer,
  authority varchar(255),
  primary key (id)
);
drop table if exists app_user CASCADE;

CREATE TABLE app_user (
  user_id  integer,
  enabled BOOLEAN not null,
  name varchar(255) not null,
  password varchar(255) not null,
  version integer,
  last_password_reset_date TIMESTAMP DEFAULT Now(),
  email VARCHAR(255) not null,
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
  id integer not null,
  user_id integer not null,
  expiry_date TIMESTAMP not null,
  token VARCHAR(255) not null,
  primary key (id)
);

ALTER TABLE password_reset_token
    ADD CONSTRAINT user_id FOREIGN KEY (user_id) REFERENCES app_user(user_id);

DROP TABLE IF EXISTS customer CASCADE;
CREATE TABLE customer (
    customer_id integer NOT NULL,
    customer_name text[] NOT NULL,
    customer_phone text[],
    customer_address text[]
);

DROP TABLE IF EXISTS purchase_order CASCADE;
CREATE TABLE purchase_order (
    purchase_order_id integer NOT NULL,
    purchase_order_date date NOT NULL,
    customer_id integer NOT NULL,
    app_user_id integer NOT NULL
);

DROP TABLE IF EXISTS order_detail CASCADE;
CREATE TABLE order_detail (
    order_detail_id integer NOT NULL,
    purchase_order_id integer NOT NULL,
    product_id integer NOT NULL,
    quantity integer NOT NULL
);

DROP TABLE IF EXISTS product CASCADE;
CREATE TABLE product (
    product_id integer NOT NULL,
    product_name text NOT NULL,
    product_price numeric(10,2) NOT NULL,
    product_quantity_left integer NOT NULL
);


ALTER TABLE customer
    ADD CONSTRAINT customer_pkey PRIMARY KEY (customer_id);


ALTER TABLE ONLY order_detail
    ADD CONSTRAINT order_detail_pkey PRIMARY KEY (order_detail_id);

ALTER TABLE purchase_order
    ADD CONSTRAINT purchase_order_pkey PRIMARY KEY (purchase_order_id);

ALTER TABLE product
    ADD CONSTRAINT product_pkey PRIMARY KEY (product_id);

ALTER TABLE purchase_order
    ADD CONSTRAINT customer_id FOREIGN KEY (customer_id) REFERENCES customer(customer_id);

ALTER TABLE order_detail
    ADD CONSTRAINT purchase_order_id FOREIGN KEY (purchase_order_id) REFERENCES purchase_order(purchase_order_id);
    
ALTER TABLE order_detail
    ADD CONSTRAINT product_id FOREIGN KEY (product_id) REFERENCES product(product_id);

ALTER TABLE purchase_order
    ADD CONSTRAINT app_user_id FOREIGN KEY (app_user_id) REFERENCES app_user(user_id);

