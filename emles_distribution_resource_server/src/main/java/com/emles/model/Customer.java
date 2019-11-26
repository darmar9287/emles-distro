package com.emles.model;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import com.emles.utils.Utils;

@Entity
@Table(name = "customer")
public class Customer implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "customer_id")
	private Long customerId;

	@Column(name = "customer_name", nullable = false)
	@NotNull
	@Pattern(regexp = Utils.customerNameRegex, message = Utils.invalidCustomerNameRegex)
	private String customerName;

	@Column(name = "customer_phone", nullable = false, unique = true)
	@NotNull
	@Pattern(regexp = Utils.phoneNumberRegex, message = Utils.invalidPhoneNumberMsg)
	private String customerPhone;

	@Column(name = "customer_address", nullable = false, unique = true)
	@NotNull
	@Email
	private String customerAddress;

	@OneToMany(mappedBy = "orderId")
	private List<Order> orders;

	public Customer(String customerName, String customerPhone, String customerAddress, List<Order> orders) {
		super();
		this.customerName = customerName;
		this.customerPhone = customerPhone;
		this.customerAddress = customerAddress;
		this.orders = orders;
	}

	public Customer() {
	}

	public Long getCustomerId() {
		return customerId;
	}

	public void setCustomerId(Long customerId) {
		this.customerId = customerId;
	}

	public String getCustomerName() {
		return customerName;
	}

	public void setCustomerName(String customerName) {
		this.customerName = customerName;
	}

	public String getCustomerPhone() {
		return customerPhone;
	}

	public void setCustomerPhone(String customerPhone) {
		this.customerPhone = customerPhone;
	}

	public String getCustomerAddress() {
		return customerAddress;
	}

	public void setCustomerAddress(String customerAddress) {
		this.customerAddress = customerAddress;
	}

	public List<Order> getOrders() {
		return orders;
	}

	public void setOrders(List<Order> orders) {
		this.orders = orders;
	}
}