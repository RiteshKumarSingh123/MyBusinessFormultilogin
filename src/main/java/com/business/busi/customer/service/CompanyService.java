package com.business.busi.customer.service;
import java.util.Map;
import java.util.Optional;

import com.business.busi.customer.entity.Company;
import com.business.busi.customer.entity.Customers;
import com.business.busi.customer.entity.Workers;
import com.business.busi.customer.model.CompanyDetails;



public interface CompanyService {

public Company saveCompanyInfo(Company company);
	
	public CompanyDetails getCompanyList(int page, int size);
	
	public CompanyDetails getCompanyDetailsList(int page, int size);
	
	public Optional<Company> getCompanyById(long companyId);
	
	public Map<String,String> deleteCompanyById(long companyId);
	
	public Map<String,String> updateCompany(Company company);
	
	public Map<String,String> getDuplicateCompany(long companyId);
	
	public Workers saveWorkersData(Workers worker); 
	
	public CompanyDetails getWorkersList(int page, int size);

	public Optional<Workers> getWorkersById(long workerId);
	
	public Map<String,String> deleteWorkerById(long workerId);
	
	public Map<String,String> updateWorkers(Workers worker);
	
	public Customers saveCustomersData(Customers customers);
	
	public CompanyDetails getCustomersList(int page ,int size);
	
	public  Optional<Customers> getCustomerById(long customerId);
	
	public Map<String,String> deleteCustomerById(long customerId);
	
	public Map<String,String> updateCustomers(Customers customers);
	
}
