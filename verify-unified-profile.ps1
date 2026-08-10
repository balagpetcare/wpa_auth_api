# Fail-fast consolidated verifier for the section-based Furtail Profile
# Settings implementation. Checks $LASTEXITCODE after every native command
# and exits immediately on failure. Run from any directory.

$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [string]$Description,
        [string]$WorkingDirectory,
        [string]$Command
    )
    Write-Host "==> $Description" -ForegroundColor Cyan
    Push-Location $WorkingDirectory
    try {
        Invoke-Expression $Command
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAILED (exit $LASTEXITCODE): $Description" -ForegroundColor Red
            exit $LASTEXITCODE
        }
        Write-Host "OK" -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

# ---- Central Auth API ----
Invoke-Checked "Central Auth: typecheck" "D:\wpa\wpa_auth\wpa_auth_api" "npm run check"
Invoke-Checked "Central Auth: prisma migrate status" "D:\wpa\wpa_auth\wpa_auth_api" "npx prisma migrate status"
Invoke-Checked "Central Auth: prisma migrate deploy (idempotency check #1)" "D:\wpa\wpa_auth\wpa_auth_api" "npx prisma migrate deploy"
Invoke-Checked "Central Auth: prisma migrate deploy (idempotency check #2)" "D:\wpa\wpa_auth\wpa_auth_api" "npx prisma migrate deploy"
Invoke-Checked "Central Auth: identity/verification integration tests" "D:\wpa\wpa_auth\wpa_auth_api" "npx tsx --test src/modules/auth/centralAuth.integration.test.ts"

# ---- Furtail API ----
Invoke-Checked "Furtail API: typecheck" "D:\wpa\furtail\furtail_app_api" "npm run typecheck"
Invoke-Checked "Furtail API: lint" "D:\wpa\furtail\furtail_app_api" "npm run lint"
Invoke-Checked "Furtail API: prisma migrate status" "D:\wpa\furtail\furtail_app_api" "npx prisma migrate status"
Invoke-Checked "Furtail API: prisma migrate deploy (idempotency check #1)" "D:\wpa\furtail\furtail_app_api" "npx prisma migrate deploy"
Invoke-Checked "Furtail API: prisma migrate deploy (idempotency check #2)" "D:\wpa\furtail\furtail_app_api" "npx prisma migrate deploy"
Invoke-Checked "Furtail API: shared-user-profile + DOB migration unit tests" "D:\wpa\furtail\furtail_app_api" "npx jest tests/shared-user-profile.unit.test.ts tests/migrate-dob-to-central-auth.unit.test.ts --config jest.config.js --runInBand"
Invoke-Checked "Furtail API: fundraising privacy + donor anonymity + author-safety tests" "D:\wpa\furtail\furtail_app_api" "npx jest tests/fundraising-privacy.integration.test.ts --config jest.config.js --runInBand"
Invoke-Checked "Furtail API: fundraising full suite (serial - see report for the parallel-worker race caveat)" "D:\wpa\furtail\furtail_app_api" "npx jest tests/fundraising.integration.test.ts tests/fundraising-visibility.integration.test.ts tests/fundraising-donation-persistence.integration.test.ts --config jest.config.js --runInBand"
Invoke-Checked "Furtail API: social/security (JWT audience/expiry/signature, birthdate isolation)" "D:\wpa\furtail\furtail_app_api" "npx jest tests/social.integration.test.ts tests/security.test.ts --config jest.config.js --runInBand"
Invoke-Checked "Furtail API: adoption suite" "D:\wpa\furtail\furtail_app_api" "npx jest tests/adoption.integration.test.ts tests/modules/adoption/adoption-store.test.ts --config jest.config.js --runInBand"

# ---- Furtail Flutter ----
Invoke-Checked "Furtail Flutter: analyze profile module (hub + settings sections)" "D:\wpa\furtail\furtail_app" "flutter analyze --no-pub lib/features/profile/ lib/core/auth/central_auth_api.dart"
Invoke-Checked "Furtail Flutter: public-profile settings section tests" "D:\wpa\furtail\furtail_app" "flutter test test/features/profile/settings/public_profile_screen_test.dart --no-pub"
Invoke-Checked "Furtail Flutter: pet Create/Edit/image tests" "D:\wpa\furtail\furtail_app" "flutter test test/features/pets/ --no-pub"

# ---- BPA Flutter (compatibility reference) ----
Invoke-Checked "BPA Flutter: analyze (scoped to shared-profile compatibility surface)" "D:\bpa_main\bpa_user_app" "flutter analyze --no-pub lib/services/api/central_auth_api_service.dart lib/features/profile/"
Invoke-Checked "BPA Flutter: shared-profile compatibility tests" "D:\bpa_main\bpa_user_app" "flutter test test/shared_profile_models_test.dart test/shared_profile_controller_test.dart test/edit_profile_screen_test.dart --no-pub"

Write-Host ""
Write-Host "ALL CHECKS PASSED" -ForegroundColor Green
