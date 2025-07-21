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
        Schema::create('balasan', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap balasan
            $table->unsignedBigInteger('id_pasien')->nullable(); // Foreign key merujuk pada pasien yang memberikan balasan
            $table->uuid('id_diskusi'); // Foreign key merujuk pada diskusi terkait
            $table->string('isi', 255); // Isi balasan yang diberikan oleh pasien
            $table->timestamps(); // Menambahkan kolom created_at dan updated_at

            // Definisi foreign key
            $table->foreign('id_pasien')->references('id')->on('pasien')->onDelete('set null');
            $table->foreign('id_diskusi')->references('id')->on('diskusi')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('balasan');
    }
};
