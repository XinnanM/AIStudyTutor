package com.abx.model.repository;

import com.abx.model.model.LanguageEntity;
import java.util.UUID;
import org.springframework.data.repository.CrudRepository;

public interface LanguageRepository extends CrudRepository<LanguageEntity, UUID> {}
