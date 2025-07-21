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
        Schema::create('admin', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap admin
            $table->unsignedBigInteger('id_user'); // Foreign key merujuk pada ID pengguna di tabel Users
            $table->enum('admin_role', ['superadmin', 'content admin']); // Peran atau tanggung jawab admin

            // Definisi foreign key
            $table->foreign('id_user')->references('id')->on('user')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('admin');
    }
};
