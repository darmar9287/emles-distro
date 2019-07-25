DROP TABLE IF EXISTS customer CASCADE;
CREATE TABLE customer (
    customer_id integer NOT NULL,
    customer_name text[] NOT NULL,
    customer_phone text[],
    customer_address text[]
);

DROP TABLE IF EXISTS orders CASCADE;
CREATE TABLE orders (
    order_id integer NOT NULL,
    order_date date NOT NULL,
    customer_id integer NOT NULL,
    app_user_id integer NOT NULL
);

DROP TABLE IF EXISTS order_detail CASCADE;
CREATE TABLE order_detail (
    order_detail_id integer NOT NULL,
    order_id integer NOT NULL,
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
    ADD CONSTRAINT app_user_id FOREIGN KEY (app_user_id) REFERENCES app_user(id);

