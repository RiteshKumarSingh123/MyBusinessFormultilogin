package com.business.busi.customer.entity;

import org.hibernate.annotations.Filter;
import org.hibernate.annotations.FilterDef;
import org.hibernate.annotations.ParamDef;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name="customers" ,
uniqueConstraints = {@UniqueConstraint(columnNames ="customer_name")})
@FilterDef(name = "customersFilter", parameters = {
        @ParamDef(name = "customerId",          type = Long.class),
        @ParamDef(name = "customerName",        type = String.class),
        @ParamDef(name = "customerAdress",      type = String.class),
        @ParamDef(name = "customerAge",         type = String.class),
          })
@Filter(
	    name = "customersFilter",
	    condition = "(:customerId is null or customer_id = :customerId) " +
	                "and (:customerName is null or customer_name = :customerName) " +
	                "and (:customerAdress is null or customer_adress = :customerAdress) " +
	                "and (:customerAge is null or customer_age = :customerAge) " 
	   )
 public class Customers {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
 @Column(name="customer_id", nullable = false)
 private long   customerId;
 @Column(name="customer_name",  length = 50, nullable = false)
 private String customerName;
 @Column(name="customer_adress",length = 100,nullable = false)
 private String customerAdress;
 @Column(name="customer_age", nullable = false)
 private String customerAge;
 public long getCustomerId() {
	return customerId;
 }
 public void setCustomerId(long customerId) {
	this.customerId = customerId;
 }
 public String getCustomerName() {
	return customerName;
 }
 public void setCustomerName(String customerName) {
	this.customerName = customerName;
 }
 
 public String getCustomerAdress() {
	return customerAdress;
 }
 public void setCustomerAdress(String customerAdress) {
	this.customerAdress = customerAdress;
 }
 public String getCustomerAge() {
	return customerAge;
 }
 public void setCustomerAge(String customerAge) {
	this.customerAge = customerAge;
 }


 @Override
 public String toString() {
	return "Customers [customerId=" + customerId + ", customerName=" + customerName + ", customerAdress="
			+ customerAdress + ", customerAge=" + customerAge + "]";
 }
 
 
 }
