package com.emles.repository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.emles.model.Product;

import java.util.List;


@Repository
public interface ProductRepository extends JpaRepository<Product,Long> {

    Product findByProductName(String name);
    List<Product> findAll();
}