package com.emles.service;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.emles.model.AppUser;
import com.emles.model.Customer;
import com.emles.model.Order;
import com.emles.model.Product;
import com.emles.model.OrderDetail;
import com.emles.repository.OrderDetailRepository;
import com.emles.repository.OrderRepository;
import com.emles.repository.ProductRepository;

@Service
public class OrderService {
	
	@Autowired
	OrderRepository orderRepository;
	
	@Autowired
	ProductRepository productRepository;
	
	@Autowired
	OrderDetailRepository orderDetailRepository;	

	@Transactional
	public void addOrder(AppUser user, Customer customer, Map<Product, Integer> products) {
		Date date = new Date();		
		Order order = new Order();
		List<OrderDetail> orderDetails = order.getOrderDetails();
		for (Map.Entry<Product, Integer> entry : products.entrySet()) {
		    System.out.println(entry.getKey() + "/" + entry.getValue());
		    OrderDetail orderDetail = new OrderDetail();
		    orderDetail.setProduct(entry.getKey());
		    orderDetail.setQuantity(entry.getValue());
		    orderDetails.add(orderDetail);
		    orderDetailRepository.save(orderDetail);
		}
		order.setCustomer(customer);
		order.setOrderDate(date);
		order.setOrderDetails(orderDetails);	
		orderRepository.save(order);
	}

}