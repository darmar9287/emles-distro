package com.emles.model;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "purchase_order")
public class PurchaseOrder implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long purchaseOrderId;

	@Temporal(TemporalType.DATE)
	@Column(name = "purchase_order_date", nullable = false)
	private Date orderDate;

	@ManyToOne(fetch = FetchType.EAGER, cascade=CascadeType.ALL)
	@JoinColumn(name = "customer_id", nullable = false)
	private Customer customerId;
	
	@OneToMany(mappedBy="orderDetailId")
	private List<OrderDetail> orderDetails;

	public PurchaseOrder() {
		
	}
	
	public PurchaseOrder(Date orderDate, Customer customerId, List<OrderDetail> orderDetails) {
		super();
		this.orderDate = orderDate;
		this.customerId = customerId;
		this.orderDetails = orderDetails;		
	}

	public Long getOrderId() {
		return purchaseOrderId;
	}

	public void setOrderId(Long orderId) {
		this.purchaseOrderId = orderId;
	}

	public Date getOrderDate() {
		return orderDate;
	}

	public void setOrderDate(Date orderDate) {
		this.orderDate = orderDate;
	}

	public Customer getCustomerId() {
		return customerId;
	}

	public void setCustomerId(Customer customerId) {
		this.customerId = customerId;
	}

	public List<OrderDetail> getOrderDetails() {
		return orderDetails;
	}

	public void setOrderDetails(List<OrderDetail> orderDetails) {
		this.orderDetails = orderDetails;
	}
}