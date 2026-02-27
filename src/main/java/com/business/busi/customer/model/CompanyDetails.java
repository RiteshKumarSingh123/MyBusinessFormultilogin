package com.business.busi.customer.model;

import java.util.List;

import com.business.busi.customer.entity.Company;
import com.business.busi.customer.entity.Customers;
import com.business.busi.customer.entity.Workers;


public class CompanyDetails {
private long count;
private List<Company> companyFilter;
private List<Workers> workersFilter;
private List<Customers> customersFilter;
private long totalPages;
private long currentPage;

public long getCurrentPage() {
	return currentPage;
}
public void setCurrentPage(long currentPage) {
	this.currentPage = currentPage;
}
public long getTotalPages() {
	return totalPages;
}
public void setTotalPages(long totalPages) {
	this.totalPages = totalPages;
}
public long getCount() {
	return count;
}
public void setCount(long count) {
	this.count = count;
}
public List<Company> getCompanyFilter() {
	return companyFilter;
}
public void setCompanyFilter(List<Company> companyFilter) {
	this.companyFilter = companyFilter;
}
public List<Workers> getWorkersFilter() {
	return workersFilter;
}
public void setWorkersFilter(List<Workers> workersFilter) {
	this.workersFilter = workersFilter;
}
public List<Customers> getCustomersFilter() {
	return customersFilter;
}
public void setCustomersFilter(List<Customers> customersFilter) {
	this.customersFilter = customersFilter;
}
@Override
public String toString() {
	return "CompanyDetails [count=" + count + ", companyFilter=" + companyFilter + ", workersFilter=" + workersFilter
			+ "]";
}


}
