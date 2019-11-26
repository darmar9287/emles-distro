package com.emles.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.emles.model.Customer;

@Repository
public interface CustomerRepository extends JpaRepository <Customer, Long> {

	@Query(value = "from Customer c WHERE c.customerName LIKE %?1%",
			countQuery = "SELECT COUNT(c) FROM Customer c WHERE c.customerName LIKE %?1%", nativeQuery = false)
	Page<Customer> findByName(String name, Pageable pageable);
	
	Customer findByCustomerPhone(String customerPhone);
	
	Customer findByCustomerAddress(String customerAddress);
}
