package com.business.busi.customer.repository;

import java.io.Serializable;

import org.springframework.data.jpa.repository.JpaRepository;

import com.business.busi.customer.entity.Customers;


public interface CustomersRepository extends JpaRepository<Customers, Serializable> {

}
