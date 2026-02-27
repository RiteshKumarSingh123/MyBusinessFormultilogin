package com.business.busi.customer.repository;

import java.io.Serializable;

import org.springframework.data.jpa.repository.JpaRepository;

import com.business.busi.customer.entity.Workers;


public interface WorkersRepository extends JpaRepository<Workers, Serializable>{

}
