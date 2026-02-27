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

@Entity
@Table(name ="company")
@FilterDef(name = "companyFilter", parameters = { @ParamDef(name = "companyId",           type = Long.class),
		                                          @ParamDef(name = "companyName",         type = String.class),
		                                          @ParamDef(name = "companyAddress",      type = String.class),
		                                          @ParamDef(name = "companyTotalMembers", type = String.class),
                                                  @ParamDef(name = "ownerName",           type = String.class),
                                                  @ParamDef(name = "companyProducts",     type = String.class),
                                                  @ParamDef(name = "workingHours",        type = String.class)
})
@Filter(
	    name = "companyFilter",
	    condition = "(:companyId is null or company_id = :companyId) " +
	                "and (:companyName is null or company_name = :companyName) " +
	                "and (:companyAddress is null or company_address = :companyAddress) " +
	                "and (:companyTotalMembers is null or company_total_members = :companyTotalMembers) " +
	                "and (:ownerName is null or owner_name = :ownerName)" +
	                "and (:companyProducts is null or company_products = :companyProducts)" +
	                "and (:workingHours is null or working_hours = :workingHours)"
	)
public class Company {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)

	@Column(name = "company_id")
    private long companyId;
	@Column(name = "company_name")
    private String companyName;
	@Column(name = "company_address")
    private String companyAddress;
	@Column(name = "company_total_members")
    private String companyTotalMembers;
	@Column(name = "owner_name")
    private String ownerName;
	@Column(name = "company_products")
    private String companyProducts;
	@Column(name = "working_hours")
    private String workingHours;

  public long getCompanyId() {
	return companyId;
  }
  public void setCompanyId(long companyId) {
	this.companyId = companyId;
  }
  public String getCompanyName() {
	return companyName;
  }
  public void setCompanyName(String companyName) {
	this.companyName = companyName;
  }
  public String getCompanyAddress() {
	return companyAddress;
  }
  public void setCompanyAddress(String companyAddress) {
	this.companyAddress = companyAddress;
  }
  public String getCompanyTotalMembers() {
	return companyTotalMembers;
  }
  public void setCompanyTotalMembers(String companyTotalMembers) {
	this.companyTotalMembers = companyTotalMembers;
  }
  public String getOwnerName() {
	return ownerName;
  }
  public void setOwnerName(String ownerName) {
	this.ownerName = ownerName;
  }
  public String getCompanyProducts() {
	return companyProducts;
  }
  public void setCompanyProducts(String companyProducts) {
	this.companyProducts = companyProducts;
  }
  public String getWorkingHours() {
	return workingHours;
  }
  public void setWorkingHours(String workingHours) {
	this.workingHours = workingHours;
  }


  @Override
  public String toString() {
	return "Company [companyId=" + companyId + ", companyName=" + companyName + ", companyAddress=" + companyAddress
			+ ", companyTotalMembers=" + companyTotalMembers + ", ownerName=" + ownerName + ", companyProducts="
			+ companyProducts + ", workingHours=" + workingHours + "]";
  }


}
