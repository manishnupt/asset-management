package com.hrms.asset.management.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.hrms.asset.management.request.AssetAllocationRequest;
import com.hrms.asset.management.request.AssetReportRequest;
import com.hrms.asset.management.request.AssetRequest;
import com.hrms.asset.management.request.AssetRequestSubmission;
import com.hrms.asset.management.request.AssetReturnRequest;
import com.hrms.asset.management.response.AssetAllocationResponse;
import com.hrms.asset.management.response.AssetReportResponse;
import com.hrms.asset.management.response.AssetRequestResponse;
import com.hrms.asset.management.response.AssetResponse;
import com.hrms.asset.management.response.AssetReturnResponse;
import com.hrms.asset.management.service.AssetService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/asset")
@CrossOrigin(origins="*")
public class AssetController {

    @Autowired
    private AssetService assetService;

    /* Asset */
    @PostMapping
    public ResponseEntity<AssetResponse> addAsset(@Valid @RequestBody AssetRequest assetRequest) {
        AssetResponse asset = assetService.addAsset(assetRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(asset);
    }

    @PatchMapping("/allocate/{assetId}")
    public ResponseEntity<AssetAllocationResponse> allocateAsset(@PathVariable Long assetId,
            @Valid @RequestBody AssetAllocationRequest assetRequest) {

                AssetAllocationResponse updatedAsset = assetService.allocateAsset(assetId, assetRequest);

        return ResponseEntity.status(HttpStatus.OK).body(updatedAsset);

    }
    @PatchMapping("/report/{assetId}")
    public ResponseEntity<AssetReportResponse> reportAsset(@PathVariable Long assetId,
            @Valid @RequestBody AssetReportRequest assetRequest) {

        AssetReportResponse updatedAsset = assetService.reportAsset(assetId, assetRequest);

        return ResponseEntity.status(HttpStatus.OK).body(updatedAsset);

    }
    @PatchMapping("/return/{assetId}")
    public ResponseEntity<AssetReturnResponse> returnAsset(@PathVariable Long assetId,
            @Valid @RequestBody AssetReturnRequest assetRequest) {

        AssetReturnResponse updatedAsset = assetService.returnAsset(assetId, assetRequest);

        return ResponseEntity.status(HttpStatus.OK).body(updatedAsset);

    }

    @PatchMapping("/{id}")
    public ResponseEntity<AssetResponse> updateAsset(@PathVariable Long id,
            @Valid @RequestBody AssetRequest assetRequest) {

        AssetResponse updatedAsset = assetService.updateAsset(id, assetRequest);

        return ResponseEntity.status(HttpStatus.OK).body(updatedAsset);

    }

    @GetMapping
    public ResponseEntity<List<AssetResponse>> getAllAsset(@RequestParam(required = false) String status,
            @RequestParam(required = false) String assetType) {

        List<AssetResponse> assetResponse = assetService.getAllAsset(status,assetType);
        if (assetResponse != null) {
            return ResponseEntity.ok(assetResponse);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /* Asset Request */

    @PostMapping("/request")
    public ResponseEntity<AssetRequestResponse> requestAsset(@RequestParam String employeeId,
            @Valid @RequestBody AssetRequestSubmission assetRequestSubmission) {

        AssetRequestResponse assetRespone = assetService.requestAsset(employeeId, assetRequestSubmission);
        return ResponseEntity.status(HttpStatus.OK).body(assetRespone);

    }

    @GetMapping("/request")
    public ResponseEntity<List<AssetRequestResponse>> getAllRequestedAsset(@RequestParam String employeeId) {

        List<AssetRequestResponse> assetResponse = assetService.getAllRequestedAsset(employeeId);
        if (assetResponse != null) {
            return ResponseEntity.ok(assetResponse);
        } else {
            return ResponseEntity.notFound().build();
        }
    }
    //api to get assets by employee id
    @PreAuthorize("hasRole('XYZ')")
    @GetMapping("/employee")
    public ResponseEntity<List<AssetResponse>> getAssetsByEmployee(@RequestParam String employeeId) {
        List<AssetResponse> assetRespone = assetService.getAssetsByEmployee(employeeId);
        return ResponseEntity.status(HttpStatus.OK).body(assetRespone);

    }

}
