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
        Schema::create('aktivitas_positif', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap aktivitas positif
            $table->string('nama', 255); // Nama aktivitas positif
            $table->string('gambar', 255); // Gambar dari aktivitas positif
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('aktivitas_positif');
    }
};
