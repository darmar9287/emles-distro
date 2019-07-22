--
-- PostgreSQL database dump
--

-- Dumped from database version 11.4
-- Dumped by pg_dump version 11.4

-- Started on 2019-07-23 21:05:42

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- TOC entry 8 (class 2615 OID 16396)
-- Name: emles-distribution; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA "emles-distribution";


ALTER SCHEMA "emles-distribution" OWNER TO postgres;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- TOC entry 197 (class 1259 OID 16400)
-- Name: customer; Type: TABLE; Schema: emles-distribution; Owner: postgres
--

CREATE TABLE "emles-distribution".customer (
    customer_id integer NOT NULL,
    customer_name text[] NOT NULL,
    customer_phone text[],
    customer_address text[]
);


ALTER TABLE "emles-distribution".customer OWNER TO postgres;

--
-- TOC entry 198 (class 1259 OID 16408)
-- Name: order; Type: TABLE; Schema: emles-distribution; Owner: postgres
--

CREATE TABLE "emles-distribution"."order" (
    order_id integer NOT NULL,
    order_date date NOT NULL,
    customer_id integer NOT NULL,
    user_id integer NOT NULL
);


ALTER TABLE "emles-distribution"."order" OWNER TO postgres;

--
-- TOC entry 201 (class 1259 OID 16460)
-- Name: order_detail; Type: TABLE; Schema: emles-distribution; Owner: postgres
--

CREATE TABLE "emles-distribution".order_detail (
    order_detail_id integer NOT NULL,
    order_id integer NOT NULL,
    product_id integer NOT NULL,
    quantity integer NOT NULL
);


ALTER TABLE "emles-distribution".order_detail OWNER TO postgres;

--
-- TOC entry 200 (class 1259 OID 16452)
-- Name: product; Type: TABLE; Schema: emles-distribution; Owner: postgres
--

CREATE TABLE "emles-distribution".product (
    product_id integer NOT NULL,
    product_name text NOT NULL,
    product_price text NOT NULL,
    product_quantity_left integer NOT NULL
);


ALTER TABLE "emles-distribution".product OWNER TO postgres;

--
-- TOC entry 199 (class 1259 OID 16418)
-- Name: user; Type: TABLE; Schema: emles-distribution; Owner: postgres
--

CREATE TABLE "emles-distribution"."user" (
    user_id integer NOT NULL,
    user_name text NOT NULL,
    user_password text NOT NULL,
    user_email text,
    user_phone text
);


ALTER TABLE "emles-distribution"."user" OWNER TO postgres;

--
-- TOC entry 2704 (class 2606 OID 16407)
-- Name: customer customer_pkey; Type: CONSTRAINT; Schema: emles-distribution; Owner: postgres
--

ALTER TABLE ONLY "emles-distribution".customer
    ADD CONSTRAINT customer_pkey PRIMARY KEY (customer_id);


--
-- TOC entry 2712 (class 2606 OID 16466)
-- Name: order_detail order_detail_pkey; Type: CONSTRAINT; Schema: emles-distribution; Owner: postgres
--

ALTER TABLE ONLY "emles-distribution".order_detail
    ADD CONSTRAINT order_detail_pkey PRIMARY KEY (order_detail_id);


--
-- TOC entry 2706 (class 2606 OID 16412)
-- Name: order order_pkey; Type: CONSTRAINT; Schema: emles-distribution; Owner: postgres
--

ALTER TABLE ONLY "emles-distribution"."order"
    ADD CONSTRAINT order_pkey PRIMARY KEY (order_id);


--
-- TOC entry 2710 (class 2606 OID 16459)
-- Name: product product_pkey; Type: CONSTRAINT; Schema: emles-distribution; Owner: postgres
--

ALTER TABLE ONLY "emles-distribution".product
    ADD CONSTRAINT product_pkey PRIMARY KEY (product_id);


--
-- TOC entry 2708 (class 2606 OID 16425)
-- Name: user user_pkey; Type: CONSTRAINT; Schema: emles-distribution; Owner: postgres
--

ALTER TABLE ONLY "emles-distribution"."user"
    ADD CONSTRAINT user_pkey PRIMARY KEY (user_id);


--
-- TOC entry 2713 (class 2606 OID 16413)
-- Name: order customer_id; Type: FK CONSTRAINT; Schema: emles-distribution; Owner: postgres
--

ALTER TABLE ONLY "emles-distribution"."order"
    ADD CONSTRAINT customer_id FOREIGN KEY (customer_id) REFERENCES "emles-distribution".customer(customer_id);


--
-- TOC entry 2715 (class 2606 OID 16467)
-- Name: order_detail order_id; Type: FK CONSTRAINT; Schema: emles-distribution; Owner: postgres
--

ALTER TABLE ONLY "emles-distribution".order_detail
    ADD CONSTRAINT order_id FOREIGN KEY (order_id) REFERENCES "emles-distribution"."order"(order_id);


--
-- TOC entry 2716 (class 2606 OID 16472)
-- Name: order_detail product_id; Type: FK CONSTRAINT; Schema: emles-distribution; Owner: postgres
--

ALTER TABLE ONLY "emles-distribution".order_detail
    ADD CONSTRAINT product_id FOREIGN KEY (product_id) REFERENCES "emles-distribution".product(product_id);


--
-- TOC entry 2714 (class 2606 OID 16447)
-- Name: order user_id; Type: FK CONSTRAINT; Schema: emles-distribution; Owner: postgres
--

ALTER TABLE ONLY "emles-distribution"."order"
    ADD CONSTRAINT user_id FOREIGN KEY (user_id) REFERENCES "emles-distribution"."user"(user_id);


-- Completed on 2019-07-23 21:05:42

--
-- PostgreSQL database dump complete
--

