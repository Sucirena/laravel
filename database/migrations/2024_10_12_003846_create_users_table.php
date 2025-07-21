<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('user', function (Blueprint $table) {
            $table->id(); // Primary key dengan auto-increment
            $table->enum('role', ['admin', 'pasien', 'tenaga ahli']); // Peran pengguna
            $table->string('email', 50)->unique(); // Email pengguna, unik
            $table->string('password', 255); // Password, sebaiknya terenkripsi
            $table->string('nama', 50); // Nama lengkap pengguna
            $table->enum('jenis_kelamin', ['laki laki', 'perempuan']); // Jenis kelamin
            $table->date('tanggal_lahir'); // Tanggal lahir pengguna
            $table->string('foto_profil', 255)->nullable(); // URL atau path foto profil pengguna, opsional
            $table->string('otp_code', 6)->nullable(); // OTP 6 digit
            $table->timestamp('otp_expires_at')->nullable(); // Waktu kedaluwarsa OTP
            $table->timestamp('email_verified_at')->nullable();
            $table->timestamps(); // Tanggal akun dibuat
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
