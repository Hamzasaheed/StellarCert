import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  OneToMany,
} from 'typeorm';
import { UserRole } from '../../../common/constants/roles';
import { Session } from '../../auth/entities/session.entity';

export { UserRole };

export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended',
  PENDING_VERIFICATION = 'pending_verification',
}

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  @Index()
  email: string;

  @Column({'not null': true})
  username: string;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @Column({ select: false })
  password: string;

  @Column({ type: 'varchar', nullable: true })
  phone: string | null;

  @Column({ type: 'varchar', nullable: true })
  profilePicture: string | null;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.ISSUER,
  })
  role: UserRole;

  @Column({
    type: 'enum',
    enum: UserStatus,
    default: UserStatus.PENDING_VERIFICATION,
  })
  status: UserStatus;

  @Column({ nullable: true, unique: true })
  @Index()
  stellarPublicKey: string | null;

  @Column({ default: false })
  isEmailVerified: boolean;

  @Column({ type: 'varchar', nullable: true })
  emailVerificationToken: string | null;

  @Column({ type: 'timestamp', nullable: true })
  emailVerificationExpires: Date | null;

  @Column({ type: 'varchar', nullable: true })
  passwordResetToken: string | null;

  @Column({ type: 'varchar', nullable: true })
  @Index()
  passwordResetTokenHash: string | null;

  @Column({ type: 'timestamp', nullable: true })
  passwordResetExpires: Date | null;

  @Column({ default: true })
  isActive: boolean;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any> | null;

  @Column({ default: 0 })
  loginAttempts: number;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  lockedUntil: Date | null;

  @Column({ type: 'varchar', nullable: true })
  refreshToken: string | null;

  @Column({ type: 'timestamp', nullable: true })
  refreshTokenExpires: Date | null;

  @Column({ default: 0 })
  tokenVersion: number;

  @Column({ default: false })
  twoFactorEnabled: boolean;

  @Column({ type: 'varchar', nullable: true, select: false })
  twoFactorSecret: string | null;

  @Column({ type: 'simple-array', nullable: true, select: false })
  twoFactorBackupCodes: string[] | null;

  @OneToMany(() => Session, (session) => session.user)
  sessions: Session[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Virtual property for full name
  get fullName(): string {
    return `${this.firstName} ${this.lastName}`;
  }

  // Check if account is locked
  isLocked(): boolean {
    if (!this.lockedUntil) return false;
    return new Date() < this.lockedUntil;
  }

  // Check if email verification token is valid
  isEmailVerificationTokenValid(): boolean {
    if (!this.emailVerificationToken || !this.emailVerificationExpires) {
      return false;
    }
    return new Date() < this.emailVerificationExpires;
  }

  // Check if password reset token is valid
  isPasswordResetTokenValid(): boolean {
    if (!this.passwordResetToken || !this.passwordResetExpires) {
      return false;
    }
    return new Date() < this.passwordResetExpires;
  }
}
