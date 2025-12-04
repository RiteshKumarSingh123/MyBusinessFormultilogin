package com.business.busi.repository;

import java.io.Serializable;

import org.springframework.data.jpa.repository.JpaRepository;

import com.business.busi.entity.Customer;



public interface CustomerRepository extends JpaRepository<Customer, Serializable>{
	
//	public Customer findByEmail(String email);

	public Customer findByName(String name);
}
