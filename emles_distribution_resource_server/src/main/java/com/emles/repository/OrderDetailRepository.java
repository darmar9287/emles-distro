package com.emles.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.emles.model.OrderDetail;

public interface OrderDetailRepository extends JpaRepository<OrderDetail, Long> {

}
