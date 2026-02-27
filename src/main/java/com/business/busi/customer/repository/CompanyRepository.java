package com.business.busi.customer.repository;

import java.io.Serializable;

import org.springframework.data.jpa.repository.JpaRepository;

import com.business.busi.customer.entity.Company;



public interface CompanyRepository extends JpaRepository<Company, Serializable>{

}
