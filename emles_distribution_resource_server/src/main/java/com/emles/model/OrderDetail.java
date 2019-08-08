package com.emles.model;

import java.io.Serializable;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "order_detail")
public class OrderDetail implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long orderDetailId;
	
	@ManyToOne(fetch = FetchType.EAGER, cascade=CascadeType.ALL)
	@JoinColumn(name = "purchase_order_id", nullable = false)
	private PurchaseOrder purchaseOrderId;

	@ManyToOne(fetch = FetchType.EAGER, cascade=CascadeType.ALL)
	@JoinColumn(name = "product_id", nullable = false)
	private Product productId;

	@Column(name = "quantity", nullable = false)
	private Integer quantity;

	public OrderDetail() {
		
	}

	public OrderDetail(Long orderDetailId, PurchaseOrder purchaseOrderId, Product productId, Integer quantity) {
		super();
		this.orderDetailId = orderDetailId;
		this.purchaseOrderId = purchaseOrderId;
		this.productId = productId;
		this.quantity = quantity;
	}

	public Long getOrderDetailId() {
		return orderDetailId;
	}

	public void setOrderDetailId(Long orderDetailId) {
		this.orderDetailId = orderDetailId;
	}

	public PurchaseOrder getPurchaseOrderId() {
		return purchaseOrderId;
	}

	public void setPurchaseOrderId(PurchaseOrder purchaseOrderId) {
		this.purchaseOrderId = purchaseOrderId;
	}

	public Product getProductId() {
		return productId;
	}

	public void setProductId(Product productId) {
		this.productId = productId;
	}

	public Integer getQuantity() {
		return quantity;
	}

	public void setQuantity(Integer quantity) {
		this.quantity = quantity;
	}
}

