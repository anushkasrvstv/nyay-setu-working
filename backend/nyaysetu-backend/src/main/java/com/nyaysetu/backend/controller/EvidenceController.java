package com.nyaysetu.backend.controller;

import com.nyaysetu.backend.dto.UploadEvidenceResponse;
import com.nyaysetu.backend.entity.User;
import com.nyaysetu.backend.service.AuthService;
import com.nyaysetu.backend.service.EvidenceService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.UUID;

/**
 * REST Controller for uploading and retrieving evidence linked to a legal case.
 *
 * <p><b>Security note (CVE-class: IDOR / Broken Object-Level Authorization):</b>
 * The uploader identity is derived <em>server-side</em> from the authenticated
 * JWT principal via {@code @AuthenticationPrincipal}, NOT from a client-supplied
 * request parameter. This prevents evidence impersonation — where an attacker
 * could attribute an upload to any user (e.g. a judge or police officer) by
 * simply changing an {@code uploaderId} form field. See the
 * {@code uploaderId} fix commit for full context.</p>
 */
@Tag(name = "Evidence", description = "Upload evidence files linked to a case")
@RestController
@RequestMapping("/cases/{caseId}/evidence")
@RequiredArgsConstructor
public class EvidenceController {

    private final EvidenceService evidenceService;
    private final AuthService authService;

    /**
     * Upload an evidence file and associate it with the given case.
     *
     * <p>The authenticated user's ID is resolved from the JWT token held in the
     * {@code SecurityContextHolder} — never from client input. This ensures the
     * {@code uploadedBy} field on {@link com.nyaysetu.backend.entity.CaseEvidence}
     * always reflects the real uploader, preserving chain-of-custody integrity.</p>
     *
     * @param caseId      the case to attach evidence to
     * @param file        the evidence file
     * @param userDetails injected by Spring Security from the validated JWT
     * @return the filename and URL of the uploaded evidence
     */
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public UploadEvidenceResponse uploadEvidence(
            @PathVariable UUID caseId,
            @RequestParam("file") MultipartFile file,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        // Resolve the authenticated user's database ID from the JWT principal.
        // The JWT subject stores the user's email; AuthService maps that to the
        // full User entity which carries the numeric primary key.
        User user = authService.findByEmail(userDetails.getUsername());

        // Pass the server-verified user ID — never accept it from the client.
        return evidenceService.upload(caseId, file, user.getId());
    }
}