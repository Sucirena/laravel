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
        Schema::create('aktivitas_pribadi', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap aktivitas pribadi
            $table->unsignedBigInteger('id_aktivitas_positif'); // Foreign key merujuk pada aktivitas positif terkait
            $table->unsignedBigInteger('id_pasien'); // Foreign key merujuk pada ID pasien yang melakukan aktivitas
            $table->boolean('is_completed')->default(false); // Status apakah aktivitas sudah diselesaikan

            // Definisi foreign key
            $table->foreign('id_aktivitas_positif')->references('id')->on('aktivitas_positif')->onDelete('cascade');
            $table->foreign('id_pasien')->references('id')->on('pasien')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('aktivitas_pribadi');
    }
};
