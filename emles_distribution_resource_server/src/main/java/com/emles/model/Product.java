package com.emles.model;

import javax.persistence.*;
import javax.validation.constraints.Digits;
import javax.validation.constraints.Min;
import java.io.Serializable;
import java.math.BigDecimal;
import java.util.List;

@Entity
@Table(name="product")
public class Product implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	private Long productId;
	
	@Column(name="product_name", nullable=false)
	private String productName;

	@Column(name="product_quantity_left", nullable=false)
	@Min(value=0L)
	private Long productQuantityLeft;
	
	@Column(name="product_price", nullable=false)
	@Digits(integer = 10, fraction = 2)
	private BigDecimal productPrice;

	@OneToMany(mappedBy="orderDetailId")
	private List<OrderDetail> orderDetails;
	
	public Product(String productName, Long productQuantityLeft, BigDecimal productPrice, List<OrderDetail> orderDetails) {
		super();
		this.productName = productName;
		this.productQuantityLeft = productQuantityLeft;
		this.productPrice = productPrice;
		this.orderDetails = orderDetails;
	}
	
	public Product() {}

	public Long getId() {
		return productId;
	}

	public void setId(Long id) {
		this.productId = id;
	}

	public String getName() {
		return productName;
	}

	public void setProductName(String productName) {
		this.productName = productName;
	}

	public Long getProductQuantityLeft() {
		return productQuantityLeft;
	}

	public void setProductQuantityLeft(Long productQuantityLeft) {
		this.productQuantityLeft = productQuantityLeft;
	}

	public BigDecimal getProductPrice() {
		return productPrice;
	}

	public void setProductPrice(BigDecimal productPrice) {
		this.productPrice = productPrice;
	}

	public List<OrderDetail> getOrderDetails() {
		return orderDetails;
	}

	public void setOrderDetails(List<OrderDetail> orderDetails) {
		this.orderDetails = orderDetails;
	}
}