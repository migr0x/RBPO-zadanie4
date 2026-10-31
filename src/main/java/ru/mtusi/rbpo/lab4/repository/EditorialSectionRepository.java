package ru.mtusi.rbpo.lab4.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.mtusi.rbpo.lab4.model.EditorialSection;

@Repository
public interface EditorialSectionRepository extends JpaRepository<EditorialSection, Long> {

    boolean existsByNameIgnoreCase(String name);
}
