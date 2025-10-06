-- CreateEnum
CREATE TYPE "TwoFactorMethod" AS ENUM ('TOTP', 'SMS', 'EMAIL');

-- CreateEnum
CREATE TYPE "AuditAction" AS ENUM ('TWO_FACTOR_ENABLED', 'TWO_FACTOR_DISABLED', 'TWO_FACTOR_VERIFIED', 'TWO_FACTOR_VERIFICATION_FAILED', 'TWO_FACTOR_BACKUP_CODE_USED', 'TWO_FACTOR_BACKUP_CODES_REGENERATED');

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "two_factor_backup_codes" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "two_factor_enabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "two_factor_enabled_at" TIMESTAMP(3),
ADD COLUMN     "two_factor_last_used_at" TIMESTAMP(3),
ADD COLUMN     "two_factor_method" "TwoFactorMethod" NOT NULL DEFAULT 'TOTP',
ADD COLUMN     "two_factor_secret" TEXT;
