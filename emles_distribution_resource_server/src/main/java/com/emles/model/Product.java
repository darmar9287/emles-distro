package com.emles.model;

import javax.persistence.*;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import com.emles.utils.Utils;
import java.io.Serializable;
import java.math.BigDecimal;

@Entity
@Table(name = "product")
public class Product implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "product_id")
	private Long productId;

	@Pattern(regexp = Utils.productNameRegex, message = Utils.invalidProductNameMsg)
	@Column(name = "product_name", nullable = false)
	@NotNull
	private String productName;

	@Min(value = 0L, message = Utils.invalidProductQuantityMsg)
	@Column(name = "product_quantity_left", nullable = false)
	@NotNull
	private Long productQuantityLeft;

	@Column(name = "product_price", nullable = false)
	@NotNull
	private BigDecimal productPrice;

	public Product(String productName, Long productQuantityLeft, BigDecimal productPrice) {
		super();
		this.productName = productName;
		this.productQuantityLeft = productQuantityLeft;
		this.productPrice = productPrice;
	}

	public Product() {
	}

	public Long getProductId() {
		return productId;
	}

	public void setProductId(Long id) {
		this.productId = id;
	}

	public String getProductName() {
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
}