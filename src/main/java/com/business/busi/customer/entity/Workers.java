package com.business.busi.customer.entity;

import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;
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
@Table(name ="workers",uniqueConstraints = {
	@UniqueConstraint(columnNames = "workerName")	
})
@FilterDef(name = "workersFilter", parameters = {
		                                          @ParamDef(name = "workerId",          type = Long.class),
		                                          @ParamDef(name = "workerName",        type = String.class),
		                                          @ParamDef(name = "address",           type = String.class),
		                                          @ParamDef(name = "underWhichCompany", type = String.class),
		                                          @ParamDef(name = "workerPosition",    type = String.class)
                                                    })
@Filter(
	    name = "workersFilter",
	    condition = "(:workerId is null or worker_id = :workerId) " +
	                "and (:workerName is null or worker_name = :workerName) " +
	                "and (:address is null or address = :address) " +
	                "and (:underWhichCompany is null or under_which_company = :underWhichCompany) " +
	                "and (:workerPosition is null or worker_position = :workerPosition)"
	   )
public class Workers {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="worker_id",nullable = false)
    private long workerId;
	@Column(name="worker_name",length = 50,nullable = false)
    private String workerName;
	@Column(name="address",length = 100,nullable = false)
    private String address;
	@Column(name="under_which_company",length = 50,nullable = false)
    private String underWhichCompany;
	@Column(name="worker_position",length = 50,nullable = false)
    private String workerPosition;
	@CreationTimestamp
	@Column(name="date",nullable = false)
	private LocalDateTime date;
	
    public LocalDateTime getDate() {
		return date;
	}
	public void setDate(LocalDateTime date) {
		this.date = date;
	}
	public long getWorkerId() {
	return workerId;
    }
    public void setWorkerId(long workerId) {
	this.workerId = workerId;
    }
    public String getWorkerName() {
	return workerName;
    }
    public void setWorkerName(String workerName) {
	this.workerName = workerName;
    }
    public String getAddress() {
	return address;
    }
    public void setAddress(String address) {
	this.address = address;
    }
    public String getUnderWhichCompany() {
	return underWhichCompany;
    }
    public void setUnderWhichCompany(String underWhichCompany) {
	this.underWhichCompany = underWhichCompany;
    }
    public String getWorkerPosition() {
	return workerPosition;
    }
    public void setWorkerPosition(String workerPosition) {
	this.workerPosition = workerPosition;
    }


@Override
public String toString() {
	return "Workers [workerId=" + workerId + ", workerName=" + workerName + ", address=" + address
			+ ", underWhichCompany=" + underWhichCompany + ", workerPosition=" + workerPosition + "]";
}


}
